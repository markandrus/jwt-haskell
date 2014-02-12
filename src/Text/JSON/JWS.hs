module Text.JSON.JWS
  ( -- * JSON Web Signature (JWS)
    JWS
  , toByteString
  , Key
  , jws
    -- ** Header
  , Header(..)
  , Algorithm(..)
    -- ** Payload
  , Payload(..)
  ) where

import Crypto.Hash.SHA256
import Crypto.MAC.HMAC
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Char8 as C
import Data.ByteString.Lazy (toStrict)
import Data.HashMap.Strict (fromList)
import qualified Data.Text as T

{- "base64url" Encoding -}

newtype Encoded a = Encoded { getEncoding :: BS.ByteString }
  deriving Eq

instance Show (Encoded a) where
  show = show . getEncoding

toBase64URL :: BS.ByteString -> Encoded a
toBase64URL = Encoded . C.takeWhile ((/=) '=') . B64.encode

fromBase64URL :: Encoded a -> BS.ByteString
fromBase64URL = B64.decodeLenient . getEncoding

encodeJSON :: ToJSON a => a -> Encoded a
encodeJSON = toBase64URL . toStrict . encode . toJSON

{- JSON Web Signature (JWS) -}

newtype JWS = JWS { toByteString :: BS.ByteString }
  deriving Eq

instance Show JWS where
  show = show . toByteString

type Key = BS.ByteString

jws :: ToJSON a => Key -> Header -> Payload a -> JWS
jws k h p =
  let i = signingInput h p
      s = toBase64URL . getSignature $ signature k i
  in  JWS $ getSigningInput i `C.append` ('.' `C.cons` getEncoding s)

{- Header -}

newtype Header = Header { alg :: Algorithm }
  deriving (Show, Read, Eq)

instance ToJSON Header where
  toJSON (Header alg) = object
    [ T.pack "typ" .= T.pack "JWT"
    , T.pack "alg" .= alg ]

data Algorithm = HS256  -- ^ HMAC using SHA-256
  deriving (Show, Read, Eq)

instance ToJSON Algorithm where
  toJSON = toJSON . T.pack . show

-- test1 = (==) "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
--   . getEncoding . encodeJWSHeader $ JWSHeader HS256

{- Payload -}

newtype Payload a = Payload { getPayload :: a }
  deriving (Show, Read, Eq)

instance ToJSON a => ToJSON (Payload a) where
  toJSON = toJSON . getPayload

-- test2 = encodePayload . Payload . Object $ fromList
--   [ ("iss", toJSON $ T.pack "joe")
--   , ("exp", toJSON (1300819380 :: Integer))
--   , ("http://example.com/is_root", toJSON True) ]

newtype SigningInput = SigningInput { getSigningInput :: BS.ByteString }
  deriving Eq

instance Show SigningInput where
  show = show . getSigningInput

signingInput :: ToJSON a => Header -> Payload a -> SigningInput
signingInput h p = SigningInput $ getEncoding (encodeJSON h) `C.append`
    ('.' `C.cons` getEncoding (encodeJSON p))

newtype Signature = Signature { getSignature :: BS.ByteString }
  deriving Eq

instance Show Signature where
  show = show . getSignature

signature :: Key -> SigningInput -> Signature
signature k = Signature . hmac hash (BS.length k) k . getSigningInput
