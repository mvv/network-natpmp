{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}

module Network.NATPMP
  ( PmpProto(..)
  , PmpUnsupp(..)
  , PmpReq(..)
  , PmpParsedReq(..)
  , parsePmpReq
  , deserializePmpReq
  , unsuppPmpReq
  , PmpResult(..)
  , PmpResp(..)
  , PmpParsedResp(..)
  , parsePmpResp
  , deserializePmpResp
  ) where

import Prelude hiding (print)
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import Data.Word (Word8, Word16, Word32)
import Data.Bits ((.|.), (.&.))
import Data.Monoid ((<>))
import Data.Hashable (Hashable)
import Data.Textual (Printable(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Binary (Binary)
import qualified Data.Binary as B
import qualified Data.Binary.Put as B
import qualified Data.Binary.Get as B
import Data.Serialize (Serialize)
import qualified Data.Serialize as S
import Network.IP.Addr
import Control.Monad (void)

data PmpProto = UDP | TCP
                deriving (Typeable, Generic, Show, Read, Eq, Ord, Enum)

instance Hashable PmpProto

instance Printable PmpProto where
  print UDP = "UDP"
  print TCP = "TCP"

data PmpUnsupp = PmpUnsuppVer
               | PmpUnsuppOp {-# UNPACK #-} !Word8
               deriving (Typeable, Generic, Show, Read, Eq, Ord)

instance Hashable PmpUnsupp

instance Printable PmpUnsupp where
  print PmpUnsuppVer     = "Unsupported version"
  print (PmpUnsuppOp op) = "Unsupported operation: " <> print op

data PmpReq = PmpPubAddrReq
            | PmpMapReq { pmpReqProto    ∷ PmpProto
                        , pmpReqPrivPort ∷ InetPort
                        , pmpReqPubPort  ∷ InetPort
                        , pmpReqTtl      ∷ Word32 }
            deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpReq

instance Binary PmpReq where
  put PmpPubAddrReq = B.putWord8 0 >> B.putWord8 0
  put (PmpMapReq {..}) = do
    B.putWord8 0
    B.putWord8 $ if pmpReqProto == UDP then 1 else 2
    B.putWord16be 0
    B.put pmpReqPrivPort
    B.put pmpReqPubPort
    B.put pmpReqTtl
  get = parsePmpReq >>= \case
    PmpReq req     → return req
    PmpUnsuppReq e → fail $ "NAT-PMP: " ++ print e
    PmpNotReq      → fail $ "NAT-PMP: Not a request"

instance Serialize PmpReq where
  put PmpPubAddrReq = S.putWord8 0 >> S.putWord8 0
  put (PmpMapReq {..}) = do
    S.putWord8 0
    S.putWord8 $ if pmpReqProto == UDP then 1 else 2
    S.putWord16be 0
    S.put pmpReqPrivPort
    S.put pmpReqPubPort
    S.put pmpReqTtl
  get = deserializePmpReq >>= \case
    PmpReq req     → return req
    PmpUnsuppReq e → fail $ "NAT-PMP: " ++ print e
    PmpNotReq      → fail $ "NAT-PMP: Not a request"

data PmpParsedReq = PmpReq PmpReq
                  | PmpUnsuppReq PmpUnsupp
                  | PmpNotReq
                  deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpParsedReq

parsePmpReq ∷ B.Get PmpParsedReq
parsePmpReq = do
  v ← B.getWord8
  if v /= 0
  then return $ PmpUnsuppReq PmpUnsuppVer
  else do
    op ← B.getWord8
    if op == 0
    then return $ PmpReq PmpPubAddrReq
    else if op > 2
         then if op >= 128
              then return PmpNotReq
              else return $ PmpUnsuppReq $ PmpUnsuppOp op
         else do
           let p = if op == 1 then UDP else TCP
           void $ B.getWord16be
           privPort ← B.get
           pubPort  ← B.get
           ttl      ← B.get
           return $ PmpReq $ PmpMapReq { pmpReqProto    = p
                                       , pmpReqPrivPort = privPort
                                       , pmpReqPubPort  = pubPort
                                       , pmpReqTtl      = ttl }

deserializePmpReq ∷ S.Get PmpParsedReq
deserializePmpReq = do
  v ← S.getWord8
  if v /= 0
  then return $ PmpUnsuppReq PmpUnsuppVer
  else do
    op ← S.getWord8
    if op == 0
    then return $ PmpReq PmpPubAddrReq
    else if op > 2
         then if op >= 128
              then return PmpNotReq
              else return $ PmpUnsuppReq $ PmpUnsuppOp op
         else do
           let p = if op == 1 then UDP else TCP
           void $ S.getWord16be
           privPort ← S.get
           pubPort  ← S.get
           ttl      ← S.get
           return $ PmpReq $ PmpMapReq { pmpReqProto    = p
                                       , pmpReqPrivPort = privPort
                                       , pmpReqPubPort  = pubPort
                                       , pmpReqTtl      = ttl }

unsuppPmpReq ∷ ByteString → Maybe ByteString
unsuppPmpReq bs
  | BS.length bs >= 4, rest ← BS.drop 4 bs
  = Just $ BS.pack [0, BS.index bs 1 .|. 0x80, 0, 5] <> rest
  | otherwise = Nothing

data PmpResult = PmpSuccess
               | PmpNotAuthd
               | PmpNetFailure
               | PmpOutOfRes
               | PmpFatal
               deriving (Typeable, Generic, Show, Read, Eq, Ord, Enum)

instance Hashable PmpResult

instance Printable PmpResult where
  print PmpSuccess    = "Success"
  print PmpNotAuthd   = "Not authorized"
  print PmpNetFailure = "Network failure"
  print PmpOutOfRes   = "Out of resources"
  print PmpFatal      = "Fatal error"

pmpR2C ∷ PmpResult → Word16
pmpR2C PmpSuccess    = 0
pmpR2C PmpNotAuthd   = 2
pmpR2C PmpNetFailure = 3
pmpR2C PmpOutOfRes   = 4
pmpR2C PmpFatal      = 0xFFFF

pmpC2R ∷ Word16 → Either PmpUnsupp PmpResult
pmpC2R 0 = Right PmpSuccess
pmpC2R 1 = Left PmpUnsuppVer
pmpC2R 2 = Right PmpNotAuthd
pmpC2R 3 = Right PmpNetFailure
pmpC2R 4 = Right PmpOutOfRes
pmpC2R 5 = Left (PmpUnsuppOp 0)
pmpC2R _ = Right PmpFatal

data PmpResp = PmpUnsuppVerResp { pmpRespTs ∷ Word32 }
             | PmpUnsuppOpResp { pmpRespOp ∷ Word8 }
             | PmpPubAddrResp { pmpRespResult ∷ PmpResult
                              , pmpRespTs     ∷ Word32
                              , pmpRespAddr   ∷ IP4 }
             | PmpMapResp { pmpRespProto    ∷ PmpProto
                          , pmpRespResult   ∷ PmpResult
                          , pmpRespTs       ∷ Word32
                          , pmpRespPrivPort ∷ InetPort
                          , pmpRespPubPort  ∷ InetPort
                          , pmpRespTtl      ∷ Word32 }
             deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpResp

instance Binary PmpResp where
  put (PmpUnsuppVerResp {..}) = do
    B.putWord8 0
    B.putWord8 0
    B.putWord16be 1
    B.put pmpRespTs
  put (PmpUnsuppOpResp {..}) = do
    B.putWord8 0
    B.putWord8 $ pmpRespOp .|. 0x80
    B.putWord16be 5
  put (PmpPubAddrResp {..}) = do
    B.putWord8 0
    B.putWord8 128
    B.putWord16be $ pmpR2C pmpRespResult
    B.put pmpRespTs
    B.put pmpRespAddr
  put (PmpMapResp {..}) = do
    B.putWord8 0
    B.putWord8 $ if pmpRespProto == UDP then 129 else 130
    B.putWord16be $ pmpR2C pmpRespResult
    B.put pmpRespTs
    B.put pmpRespPrivPort
    B.put pmpRespPubPort
    B.put pmpRespTtl
  get = parsePmpResp >>= \case
    PmpResp resp    → return resp
    PmpUnsuppResp e → fail $ "NAT-PMP: " ++ print e
    PmpNotResp      → fail $ "NAT-PMP: Not a response"

instance Serialize PmpResp where
  put (PmpUnsuppVerResp {..}) = do
    S.putWord8 0
    S.putWord8 0
    S.putWord16be 1
    S.put pmpRespTs
  put (PmpUnsuppOpResp {..}) = do
    S.putWord8 0
    S.putWord8 $ pmpRespOp .|. 0x80
    S.putWord16be 5
  put (PmpPubAddrResp {..}) = do
    S.putWord8 0
    S.putWord8 128
    S.putWord16be $ pmpR2C pmpRespResult
    S.put pmpRespTs
    S.put pmpRespAddr
  put (PmpMapResp {..}) = do
    S.putWord8 0
    S.putWord8 $ if pmpRespProto == UDP then 129 else 130
    S.putWord16be $ pmpR2C pmpRespResult
    S.put pmpRespTs
    S.put pmpRespPrivPort
    S.put pmpRespPubPort
    S.put pmpRespTtl
  get = deserializePmpResp >>= \case
    PmpResp resp    → return resp
    PmpUnsuppResp e → fail $ "NAT-PMP: " ++ print e
    PmpNotResp      → fail $ "NAT-PMP: Not a response"

data PmpParsedResp = PmpResp PmpResp
                   | PmpUnsuppResp PmpUnsupp
                   | PmpNotResp
                   deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpParsedResp

parsePmpResp ∷ B.Get PmpParsedResp
parsePmpResp = do
  v ← B.getWord8
  if v /= 0
  then return $ PmpUnsuppResp PmpUnsuppVer
  else do
    op ← B.getWord8
    if op < 128
    then if op /= 0
         then return PmpNotResp
         else fmap pmpC2R B.getWord16be >>= \case
           Left PmpUnsuppVer → do
             ts ← B.get
             return $ PmpResp $ PmpUnsuppVerResp ts
           _ → return PmpNotResp
    else if op > 130
         then fmap pmpC2R B.getWord16be >>= \case
           Left (PmpUnsuppOp _) →
             return $ PmpResp $ PmpUnsuppOpResp $ op .&. 0x7F
           _ → return $ PmpUnsuppResp $ PmpUnsuppOp op
         else fmap pmpC2R B.getWord16be >>= \case
           Left PmpUnsuppVer → do
             ts ← B.get
             return $ PmpResp $ PmpUnsuppVerResp ts
           Left (PmpUnsuppOp _) →
             return $ PmpResp $ PmpUnsuppOpResp $ op .&. 0x7F
           Right r | op == 128 → do
             ts   ← B.get
             addr ← B.get
             return $ PmpResp $ PmpPubAddrResp { pmpRespResult = r
                                               , pmpRespTs     = ts
                                               , pmpRespAddr   = addr }
           Right r → do
             let p = if op == 129 then UDP else TCP
             ts       ← B.get
             privPort ← B.get
             pubPort  ← B.get
             ttl      ← B.get
             return $ PmpResp $ PmpMapResp { pmpRespProto    = p
                                           , pmpRespResult   = r
                                           , pmpRespTs       = ts
                                           , pmpRespPrivPort = privPort
                                           , pmpRespPubPort  = pubPort
                                           , pmpRespTtl      = ttl }

deserializePmpResp ∷ S.Get PmpParsedResp
deserializePmpResp = do
  v ← S.getWord8
  if v /= 0
  then return $ PmpUnsuppResp PmpUnsuppVer
  else do
    op ← S.getWord8
    if op < 128
    then if op /= 0
         then return PmpNotResp
         else fmap pmpC2R S.getWord16be >>= \case
           Left PmpUnsuppVer → do
             ts ← S.get
             return $ PmpResp $ PmpUnsuppVerResp ts
           _ → return PmpNotResp
    else if op > 130
         then fmap pmpC2R S.getWord16be >>= \case
           Left (PmpUnsuppOp _) →
             return $ PmpResp $ PmpUnsuppOpResp $ op .&. 0x7F
           _ → return $ PmpUnsuppResp $ PmpUnsuppOp op
         else fmap pmpC2R S.getWord16be >>= \case
           Left PmpUnsuppVer → do
             ts ← S.get
             return $ PmpResp $ PmpUnsuppVerResp ts
           Left (PmpUnsuppOp _) →
             return $ PmpResp $ PmpUnsuppOpResp $ op .&. 0x7F
           Right r | op == 128 → do
             ts   ← S.get
             addr ← S.get
             return $ PmpResp $ PmpPubAddrResp { pmpRespResult = r
                                               , pmpRespTs     = ts
                                               , pmpRespAddr   = addr }
           Right r → do
             let p = if op == 129 then UDP else TCP
             ts       ← S.get
             privPort ← S.get
             pubPort  ← S.get
             ttl      ← S.get
             return $ PmpResp $ PmpMapResp { pmpRespProto    = p
                                           , pmpRespResult   = r
                                           , pmpRespTs       = ts
                                           , pmpRespPrivPort = privPort
                                           , pmpRespPubPort  = pubPort
                                           , pmpRespTtl      = ttl }

