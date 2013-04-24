{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import qualified Data.ByteString as BS
import Data.Serialize (encode, runGet)
import Network.IP.Addr
import Network.NATPMP

main = defaultMain
  [ testGroup "PmpReq"
      [ testProperty "PmpPubAddrReq" $
          let msg = BS.pack [ 0, 0 ] in
            case runGet deserializePmpReq msg of
              Right (PmpReq req@PmpPubAddrReq) → encode req == msg
              _                                → False
      , testProperty "PmpMapReq (UDP)" $
          let msg = BS.pack [ 0, 1, 0, 0
                            , 0x12, 0x34, 0xAB, 0xCD
                            , 0, 0x56, 0x1C, 0x20 ] in
            case runGet deserializePmpReq msg of
              Right (PmpReq req@PmpMapReq {..})
                | pmpReqProto    == UDP
                , pmpReqPrivPort == 0x1234
                , pmpReqPubPort  == 0xABCD
                , pmpReqTtl      == 0x561C20
                → encode req == msg
              _ → False
      , testProperty "PmpMapReq (TCP)" $
          let msg = BS.pack [ 0, 2, 0, 0
                            , 0xFE, 0xDC, 0x43, 0x21
                            , 0x18, 0x9B, 0x77, 0xAB ] in
            case runGet deserializePmpReq msg of
              Right (PmpReq req@PmpMapReq {..})
                | pmpReqProto    == TCP
                , pmpReqPrivPort == 0xFEDC
                , pmpReqPubPort  == 0x4321
                , pmpReqTtl      == 0x189B77AB
                → encode req == msg
              _ → False

      , testProperty "Unsupported version" $
          let msg = BS.pack [ 1 ] in
            case runGet deserializePmpReq msg of
              Right (PmpUnsuppReq PmpUnsuppVer) → True
              _                                 → False
      , testProperty "Unsupported operation" $
          let msg = BS.pack [ 0, 3 ] in
            case runGet deserializePmpReq msg of
              Right (PmpUnsuppReq (PmpUnsuppOp 3)) → True
              _                                    → False
      , testProperty "Not a request" $
          let msg = BS.pack [ 0, 128 ] in
            case runGet deserializePmpReq msg of
              Right PmpNotReq → True
              _               → False
      ]
  , testGroup "PmpResp"
      [ testProperty "PmpUnsuppVerResp" $
          let msg = BS.pack [ 0, 0, 0, 1
                            , 0x12, 0x34, 0x56, 0x78 ] in
            case runGet deserializePmpResp msg of
              Right (PmpResp resp@PmpUnsuppVerResp {..})
                | pmpRespTs     == 0x12345678
                → encode resp == msg
              _ → False
      , testProperty "PmpUnsuppOpResp" $
          let msg = BS.pack [ 0, 129, 0, 5 ] in
            case runGet deserializePmpResp msg of
              Right (PmpResp resp@(PmpUnsuppOpResp {..}))
                | pmpRespOp == 1
                → encode resp == msg
              _ → False
      , testProperty "PmpPubAddrResp (Success)" $
          let msg = BS.pack [ 0, 128, 0, 0
                            , 0x12, 0x34, 0x56, 0x78
                            , 192, 168, 100, 1 ] in
            case runGet deserializePmpResp msg of
              Right (PmpResp resp@PmpPubAddrResp {..})
                | pmpRespResult == PmpSuccess
                , pmpRespTs     == 0x12345678
                , pmpRespAddr   == ip4FromOctets 192 168 100 1
                → encode resp == msg
              _ → False
      , testProperty "PmpPubAddrResp (Not authorized)" $
          let msg = BS.pack [ 0, 128, 0, 2
                            , 0x87, 0x65, 0x43, 0x21
                            , 0, 0, 0, 0 ] in
            case runGet deserializePmpResp msg of
              Right (PmpResp resp@PmpPubAddrResp {..})
                | pmpRespResult == PmpNotAuthd
                , pmpRespTs     == 0x87654321
                , pmpRespAddr   == anyIP4
                → encode resp == msg
              _ → False
      , testProperty "PmpMapResp (UDP)" $
          let msg = BS.pack [ 0, 129, 0, 3
                            , 0x12, 0x34, 0x56, 0x78
                            , 0xAA, 0xBB, 0xCC, 0xDD
                            , 0x99, 0x88, 0x77, 0x66 ] in
            case runGet deserializePmpResp msg of
              Right (PmpResp resp@PmpMapResp {..})
                | pmpRespProto    == UDP
                , pmpRespResult   == PmpNetFailure
                , pmpRespTs       == 0x12345678
                , pmpRespPrivPort == 0xAABB
                , pmpRespPubPort  == 0xCCDD
                , pmpRespTtl      == 0x99887766
                → encode resp == msg
              _ → False
      , testProperty "PmpMapResp (TCP)" $
          let msg = BS.pack [ 0, 130, 0, 4
                            , 0x87, 0x65, 0x43, 0x21
                            , 0x11, 0x22, 0x33, 0x44
                            , 0xF5, 0x71, 0xBC, 0x14 ] in
            case runGet deserializePmpResp msg of
              Right (PmpResp resp@PmpMapResp {..})
                | pmpRespProto    == TCP
                , pmpRespResult   == PmpOutOfRes
                , pmpRespTs       == 0x87654321
                , pmpRespPrivPort == 0x1122
                , pmpRespPubPort  == 0x3344
                , pmpRespTtl      == 0xF571BC14
                → encode resp == msg
              _ → False

      , testProperty "Unsupported version" $
          let msg = BS.pack [ 1 ] in
            case runGet deserializePmpResp msg of
              Right (PmpUnsuppResp PmpUnsuppVer) → True
              _                                  → False
      , testProperty "Unsupported operation" $
          let msg = BS.pack [ 0, 131, 0, 0 ] in
            case runGet deserializePmpResp msg of
              Right (PmpUnsuppResp (PmpUnsuppOp 131)) → True
              _                                       → False
      , testProperty "Not a response" $
          let msg = BS.pack [ 0, 127 ] in
            case runGet deserializePmpResp msg of
              Right PmpNotResp → True
              _                → False
      ]
  ]

