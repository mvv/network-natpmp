{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}

module Network.NATPMP
  ( PmpProto(..)
  , PmpReq(..)
  , PmpDecodedReq(..)
  , getPmpReq
  , sgetPmpReq
  , encodePmpReq
  , decodePmpReq
  , pmpMsgData
  , PmpResult(..)
  , PmpResp(..)
  , putPmpResp
  , sputPmpResp
  , PmpDecodedResp(..)
  , getPmpResp
  , sgetPmpResp
  , encodePmpResp
  , decodePmpResp
  ) where

import Prelude hiding (print)
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import Data.Word (Word8, Word16, Word32)
import Data.Bits ((.|.), (.&.))
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

data PmpReq = PmpPubAddrReq
            | PmpMapReq { pmpReqProto    ∷ PmpProto
                        , pmpReqPrivPort ∷ InetPort
                        , pmpReqPubPort  ∷ InetPort
                        , pmpReqTtl      ∷ Word32 }
            deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpReq

instance Binary PmpReq where
  put PmpPubAddrReq =
    B.putWord8 0 >> B.putWord8 0
  put (PmpMapReq {..}) = do
    B.putWord8 0
    B.putWord8 $ if pmpReqProto == UDP then 1 else 2
    B.putWord16be 0
    B.put pmpReqPrivPort
    B.put pmpReqPubPort
    B.put pmpReqTtl
  get = getPmpReq >>= \case
    PmpReq req           → return req
    PmpUnsuppVerInReq {} → fail $ "NAT-PMP: Unsupported protocol version"
    PmpUnsuppOpInReq {}  → fail $ "NAT-PMP: Unsupported operation"
    PmpNotReq            → fail $ "NAT-PMP: Not a request"

instance Serialize PmpReq where
  put PmpPubAddrReq =
    S.putWord8 0 >> S.putWord8 0
  put (PmpMapReq {..}) = do
    S.putWord8 0
    S.putWord8 $ if pmpReqProto == UDP then 1 else 2
    S.putWord16be 0
    S.put pmpReqPrivPort
    S.put pmpReqPubPort
    S.put pmpReqTtl
  get = sgetPmpReq >>= \case
    PmpReq req           → return req
    PmpUnsuppVerInReq {} → fail $ "NAT-PMP: Unsupported protocol version"
    PmpUnsuppOpInReq {}  → fail $ "NAT-PMP: Unsupported operation"
    PmpNotReq            → fail $ "NAT-PMP: Not a request"

data PmpDecodedReq = PmpReq PmpReq
                   | PmpUnsuppVerInReq {-# UNPACK #-} !Word8
                   | PmpUnsuppOpInReq {-# UNPACK #-} !Word8 ByteString
                   | PmpNotReq
                   deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpDecodedReq

getPmpReq ∷ B.Get PmpDecodedReq
getPmpReq = do
  v ← B.getWord8
  if v /= 0
  then return $ PmpUnsuppVerInReq v
  else do
    op ← B.getWord8
    if op == 0
    then return $ PmpReq PmpPubAddrReq
    else if op > 2
         then if op >= 128
              then return PmpNotReq
              else return $ PmpUnsuppOpInReq op BS.empty
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

sgetPmpReq ∷ S.Get PmpDecodedReq
sgetPmpReq = do
  v ← S.getWord8
  if v /= 0
  then return $ PmpUnsuppVerInReq v
  else do
    op ← S.getWord8
    if op == 0
    then return $ PmpReq PmpPubAddrReq
    else if op > 2
         then if op >= 128
              then return PmpNotReq
              else return $ PmpUnsuppOpInReq op BS.empty
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

pmpMsgData ∷ ByteString → ByteString
pmpMsgData = BS.drop 4
{-# INLINE pmpMsgData #-}

encodePmpReq ∷ PmpReq → ByteString
encodePmpReq = S.encode
{-# INLINE encodePmpReq #-}

decodePmpReq ∷ ByteString → Either String PmpDecodedReq
decodePmpReq i = case S.runGet sgetPmpReq i of
  Left e                        → Left e
  Right (PmpUnsuppOpInReq op _) → Right $ PmpUnsuppOpInReq op $ pmpMsgData i
  Right r                       → Right r
{-# INLINABLE decodePmpReq #-}

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

data PmpUnsupp = PmpUnsuppVer | PmpUnsuppOp

pmpC2R ∷ Word16 → Either PmpUnsupp PmpResult
pmpC2R 0 = Right PmpSuccess
pmpC2R 1 = Left PmpUnsuppVer
pmpC2R 2 = Right PmpNotAuthd
pmpC2R 3 = Right PmpNetFailure
pmpC2R 4 = Right PmpOutOfRes
pmpC2R 5 = Left PmpUnsuppOp
pmpC2R _ = Right PmpFatal

data PmpResp = PmpUnsuppVerResp { pmpRespTs ∷ Word32 }
             | PmpUnsuppOpResp { pmpRespOp   ∷ Word8
                               , pmpRespData ∷ ByteString }
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
  put = putPmpResp' PmpHaskell
  get = getPmpResp' PmpHaskell >>= \case
    PmpResp resp          → return resp
    PmpUnsuppVerInResp {} → fail $ "NAT-PMP: Unsupported protocol version"
    PmpUnsuppOpInResp {}  → fail $ "NAT-PMP: Unsupported operation"
    PmpNotResp            → fail $ "NAT-PMP: Not a response"

instance Serialize PmpResp where
  put = sputPmpResp' PmpHaskell 
  get = sgetPmpResp' PmpHaskell >>= \case
    PmpResp resp          → return resp
    PmpUnsuppVerInResp {} → fail $ "NAT-PMP: Unsupported protocol version"
    PmpUnsuppOpInResp {}  → fail $ "NAT-PMP: Unsupported operation"
    PmpNotResp            → fail $ "NAT-PMP: Not a response"

data PmpEnv = PmpHaskell | PmpProto deriving Eq

putPmpResp' ∷ PmpEnv → PmpResp → B.Put
putPmpResp' _ (PmpUnsuppVerResp {..}) = do
  B.putWord8 0
  B.putWord8 0
  B.putWord16be 1
  B.put pmpRespTs
putPmpResp' env (PmpUnsuppOpResp {..}) = do
  B.putWord8 0
  B.putWord8 $ pmpRespOp .|. 0x80
  B.putWord16be 5
  case env of
    PmpHaskell → B.put pmpRespData
    PmpProto   → B.putByteString pmpRespData
putPmpResp' _ (PmpPubAddrResp {..}) = do
  B.putWord8 0
  B.putWord8 128
  B.putWord16be $ pmpR2C pmpRespResult
  B.put pmpRespTs
  B.put pmpRespAddr
putPmpResp' _ (PmpMapResp {..}) = do
  B.putWord8 0
  B.putWord8 $ if pmpRespProto == UDP then 129 else 130
  B.putWord16be $ pmpR2C pmpRespResult
  B.put pmpRespTs
  B.put pmpRespPrivPort
  B.put pmpRespPubPort
  B.put pmpRespTtl

putPmpResp ∷ PmpResp → B.Put
putPmpResp = putPmpResp' PmpProto
{-# INLINE putPmpResp #-}

sputPmpResp' ∷ PmpEnv → PmpResp → S.Put
sputPmpResp' _ (PmpUnsuppVerResp {..}) = do
  S.putWord8 0
  S.putWord8 0
  S.putWord16be 1
  S.put pmpRespTs
sputPmpResp' env (PmpUnsuppOpResp {..}) = do
  S.putWord8 0
  S.putWord8 $ pmpRespOp .|. 0x80
  S.putWord16be 5
  case env of
    PmpHaskell → S.put pmpRespData
    PmpProto   → S.putByteString pmpRespData
sputPmpResp' _ (PmpPubAddrResp {..}) = do
  S.putWord8 0
  S.putWord8 128
  S.putWord16be $ pmpR2C pmpRespResult
  S.put pmpRespTs
  S.put pmpRespAddr
sputPmpResp' _ (PmpMapResp {..}) = do
  S.putWord8 0
  S.putWord8 $ if pmpRespProto == UDP then 129 else 130
  S.putWord16be $ pmpR2C pmpRespResult
  S.put pmpRespTs
  S.put pmpRespPrivPort
  S.put pmpRespPubPort
  S.put pmpRespTtl

sputPmpResp ∷ PmpResp → S.Put
sputPmpResp = sputPmpResp' PmpProto
{-# INLINE sputPmpResp #-}

data PmpDecodedResp = PmpResp PmpResp
                    | PmpUnsuppVerInResp {-# UNPACK #-} !Word8
                    | PmpUnsuppOpInResp {-# UNPACK #-} !Word8
                    | PmpNotResp
                    deriving (Typeable, Generic, Show, Read, Eq)

instance Hashable PmpDecodedResp

getPmpResp' ∷ PmpEnv → B.Get PmpDecodedResp
getPmpResp' env = do
  v ← B.getWord8
  if v /= 0
  then return $ PmpUnsuppVerInResp v
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
           Left PmpUnsuppOp → do
             d ← case env of
               PmpHaskell → B.get
               PmpProto   → return BS.empty
             return $ PmpResp $ PmpUnsuppOpResp (op .&. 0x7F) d
           _ → return $ PmpUnsuppOpInResp op
         else fmap pmpC2R B.getWord16be >>= \case
           Left PmpUnsuppVer → do
             ts ← B.get
             return $ PmpResp $ PmpUnsuppVerResp ts
           Left PmpUnsuppOp → do
             d ← case env of
               PmpHaskell → B.get
               PmpProto   → return BS.empty
             return $ PmpResp $ PmpUnsuppOpResp (op .&. 0x7F) d
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

getPmpResp ∷ B.Get PmpDecodedResp
getPmpResp = getPmpResp' PmpProto
{-# INLINE getPmpResp #-}

sgetPmpResp' ∷ PmpEnv → S.Get PmpDecodedResp
sgetPmpResp' env = do
  v ← S.getWord8
  if v /= 0
  then return $ PmpUnsuppVerInResp v
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
           Left PmpUnsuppOp → do
             d ← case env of
               PmpHaskell → S.get
               PmpProto   → return BS.empty
             return $ PmpResp $ PmpUnsuppOpResp (op .&. 0x7F) d
           _ → return $ PmpUnsuppOpInResp op
         else fmap pmpC2R S.getWord16be >>= \case
           Left PmpUnsuppVer → do
             ts ← S.get
             return $ PmpResp $ PmpUnsuppVerResp ts
           Left PmpUnsuppOp → do
             d ← case env of
               PmpHaskell → S.get
               PmpProto   → return BS.empty
             return $ PmpResp $ PmpUnsuppOpResp (op .&. 0x7F) d
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

sgetPmpResp ∷ S.Get PmpDecodedResp
sgetPmpResp = sgetPmpResp' PmpProto
{-# INLINE sgetPmpResp #-}

encodePmpResp ∷ PmpResp → ByteString
encodePmpResp = S.runPut . sputPmpResp
{-# INLINE encodePmpResp #-}

decodePmpResp ∷ ByteString → Either String PmpDecodedResp
decodePmpResp i = case S.runGet sgetPmpResp i of
  Left e → Left e
  Right (PmpResp (PmpUnsuppOpResp op _)) →
    Right $ PmpResp $ PmpUnsuppOpResp op $ pmpMsgData i
  Right r → Right r

