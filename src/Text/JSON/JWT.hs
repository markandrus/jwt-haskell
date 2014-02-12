{-#LANGUAGE OverloadedStrings #-}

module Text.JSON.JWT (
  -- * JSON Web Token (JWT)
    JWT
  , toByteString
  , Key
  , jwt
  -- ** Header
  , Header
  -- ** Payload
  , Payload(..)
  , Claim
  , ClaimsSet
  ) where

import Data.Aeson
import qualified Data.ByteString as BS
import Data.HashMap.Strict (fromList)
import qualified Text.JSON.JWS as JWS

{- JSON Web Token (JWT) -}

newtype JWT = JWT { toJWS :: JWS.JWS }
  deriving Eq

instance Show JWT where
  show = show . toJWS

toByteString :: JWT -> BS.ByteString
toByteString = JWS.toByteString . toJWS

type Key = BS.ByteString

jwt :: Key -> Header -> Payload -> JWT
jwt k h = JWT . JWS.jws k h . JWS.Payload

{- Header -}

type Header = JWS.Header

{- Payload -}

newtype Payload = Payload { getPayload :: ClaimsSet }
  deriving (Show, Eq)

instance ToJSON Payload where
  toJSON = toJSON . fromList . getPayload

{- Claim -}

type Claim = (String, Value)

{- Claims Set -}

type ClaimsSet = [Claim]
