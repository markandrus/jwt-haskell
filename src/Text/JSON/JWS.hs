module Text.JSON.JWS
  ( -- * JSON Web Signature (JWS)
    JWS
  , toByteString
  , sign
    -- ** Header
  , Header(..)
    -- *** Algorithm
  , Algorithm(..)
    -- *** Type
  , Type(..)
  -- ** Payload
  , Payload
  ) where

import Crypto.Hash.SHA256
import Crypto.MAC.HMAC
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Char8 as C
import Data.ByteString.Lazy (toStrict)
import Data.HashMap.Strict (fromList)
import Data.Maybe (catMaybes)
import qualified Data.Text as T
import Network.URI

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

-- | A data structure representing a digitally signed or MACed message.
newtype JWS = JWS { toByteString :: BS.ByteString }

instance Show JWS where
  show = show . toByteString

sign :: Header -> Payload -> JWS
sign h p =
  let i = signingInput h p
      s = toBase64URL . getSignature $ signature (alg h) i
  in  JWS $ getSigningInput i `C.append` ('.' `C.cons` getEncoding s)

{- Header -}

-- TODO(mroberts): Implement.
type JWK = String

-- | JSON object containing the parameters describing the cryptographic
-- operations and parameters employed.
data Header = Header
    { alg  :: Algorithm       -- ^ Algorithm
    , jku  :: Maybe URI       -- ^ 'JWK' Set URL
    , jwk  :: Maybe JWK       -- ^ JSON Web Key
    , kid  :: Maybe String    -- ^ Key ID
    , x5u  :: Maybe URI       -- ^ X.509 URL
    , x5c  :: Maybe [String]  -- ^ X.509 Certificate Chain
    , x5t  :: Maybe String    -- ^ X.509 Certificate SHA-1 Thumbprint
    , typ  :: Maybe Type      -- ^ Type
    , cty  :: Maybe String    -- ^ Content Type
    , crit :: Maybe [String]  -- ^ Critical
    , unregistered :: [(String, Value)] }
  deriving (Show, Eq)

instance ToJSON Header where
  toJSON h = toJSON . fromList $ catMaybes
    [ Just $ T.pack "alg" .= alg h
    , fmap (\jku  -> T.pack "jku"  .= toJSON (show  jku)) $ jku  h
    , fmap (\jwk  -> T.pack "jwk"  .= toJSON        jwk)  $ jwk  h
    , fmap (\kid  -> T.pack "kid"  .= toJSON        kid)  $ kid  h
    , fmap (\x5u  -> T.pack "x5u"  .= toJSON (show  x5u)) $ x5u  h
    , fmap (\x5c  -> T.pack "x5c"  .= toJSON        x5c)  $ x5c  h
    , fmap (\x5t  -> T.pack "x5t"  .= toJSON        x5t)  $ x5t  h
    , fmap (\typ  -> T.pack "typ"  .= toJSON        typ)  $ typ  h
    , fmap (\cty  -> T.pack "cty"  .= toJSON        cty)  $ cty  h
    , fmap (\crit -> T.pack "crit" .= toJSON        crit) $ crit h
    ] ++ (map (\(k, v) -> (T.pack k, v)) $ unregistered h)

data Type
    = JWT
  deriving (Show, Eq)

instance ToJSON Type where
  toJSON = toJSON . T.pack . show

data Algorithm
    = HS256 BS.ByteString  -- ^ HMAC using SHA-256
    | None       -- ^ Plaintext
  deriving Eq

instance Show Algorithm where
  show (HS256 _) = "HS256"
  show None = "none"

instance ToJSON Algorithm where
  toJSON = toJSON . T.pack . show

-- test1 = (==) "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
--   . getEncoding . encodeJWSHeader $ JWSHeader HS256

{- Payload -}

-- | The sequence of octets to be secured — a.k.a., the message. The payload can
-- contain an arbitrary sequence of octets.
type Payload = BS.ByteString

-- test2 = encodePayload . Payload . Object $ fromList
--   [ ("iss", toJSON $ T.pack "joe")
--   , ("exp", toJSON (1300819380 :: Integer))
--   , ("http://example.com/is_root", toJSON True) ]

-- | The input to the digital signature or MAC computation.
newtype SigningInput = SigningInput { getSigningInput :: BS.ByteString }
  deriving Eq

instance Show SigningInput where
  show = show . getSigningInput

signingInput :: Header -> Payload -> SigningInput
signingInput h p = SigningInput $ getEncoding (encodeJSON h) `C.append`
    ('.' `C.cons` getEncoding (toBase64URL p))

-- | Digital signature or MAC over the 'JWS' 'Header' and the 'JWS' 'Payload'.
newtype Signature = Signature { getSignature :: BS.ByteString }
  deriving Eq

instance Show Signature where
  show = show . getSignature

-- FIXME(mroberts): Not sure the second parameter of 'hash' is correct.
signature :: Algorithm -> SigningInput -> Signature
signature (HS256 key) = Signature . hmac hash (BS.length key) key . getSigningInput
signature None = Signature . getSigningInput
