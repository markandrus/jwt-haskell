module Text.JSON.JWT (
  -- * JSON Web Token (JWT)
    JWT
  , toByteString
  , toJWS
  , sign
  -- -- ** Header
  -- , JWS.Header(..)
  -- -- *** Algorithm
  -- , JWS.Algorithm(..)
  -- -- *** Type
  -- , JWS.Type(..)
  -- ** Claims Set
  , ClaimsSet(..)
  -- *** Claim
  , Claim(..)
  , IntDate
  , StringOrURI
  , stringOrURI
  ) where

import Data.Aeson
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (toStrict)
import Data.HashMap.Strict (fromList)
import Data.Maybe (catMaybes)
import qualified Text.JSON.JWS as JWS
import Network.URI

{- IntDate -}

-- | A JSON numeric value representing the number of seconds from
-- 1970-01-01T0:0:0Z UTC until the specified UTC date/time.
type IntDate = Integer

{- StringOrURI -}

-- | A JSON string value, with the additional requirement that while arbitrary
-- string values MAY be used, any value containing a \":\" character MUST be a
-- URI.
newtype StringOrURI = StringOrURI { getStringOrURI :: Either String URI }
  deriving (Show, Eq)

instance ToJSON StringOrURI where
  toJSON = either toJSON toJSON . fmap show . getStringOrURI

-- | Parse a 'String' to a 'StringOrURI'.
stringOrURI :: String -> Maybe StringOrURI
stringOrURI string = if ':' `elem` string
  then Just . StringOrURI $ Left string
  else fmap (StringOrURI . Right) $ parseURI string

{- JSON Web Token (JWT) -}

-- | A string representing a set of claims as a JSON object that is encoded in a
-- 'JWS.JWS', enabling the claims to be digitally signed or MACed.
newtype JWT = JWT { toJWS :: JWS.JWS }

instance Show JWT where
  show = show . toJWS

toByteString :: JWT -> BS.ByteString
toByteString = JWS.toByteString . toJWS

-- | Create a 'JWT' by encoding a 'ClaimsSet' in a 'JWS.JWS'.
sign :: JWS.Header -> ClaimsSet -> JWT
sign h = JWT . JWS.sign h . toStrict . encode

{- Header -}

type Header = JWS.Header

{- Payload -}

type Payload = ClaimsSet

{- Claims Set -}

-- | A JSON object that contains the 'Claim's conveyed by the 'JWT'.
newtype ClaimsSet = ClaimsSet { toList :: [Claim] }
  deriving (Show, Eq)

instance ToJSON ClaimsSet where
  toJSON = toJSON . fromList . catMaybes . map f . toList where
    f (Iss iss)      = Just ("iss", toJSON iss)
    f (Sub sub)      = Just ("sub", toJSON sub)
    f (Aud [])       = Nothing
    f (Aud (aud:[])) = Just ("aud", toJSON aud)
    f (Aud aud)      = Just ("aud", toJSON aud)
    f (Exp exp)      = Just ("exp", toJSON exp)
    f (Nbf nbf)      = Just ("nbf", toJSON nbf)
    f (Iat iat)      = Just ("iat", toJSON iat)
    f (Jti jti)      = Just ("jti", toJSON jti)
    f (Unregistered "" _)      = Nothing
    f (Unregistered key value) = Just (key, value)

{- Claim -}

-- | A piece of information asserted about a subject.
data Claim
  = Iss StringOrURI    -- ^ Issuer
  | Sub StringOrURI    -- ^ Subject
  | Aud [StringOrURI]  -- ^ Audience
  | Exp IntDate        -- ^ Expiration Time
  | Nbf IntDate        -- ^ Not Before
  | Iat IntDate        -- ^ Issued At
  | Jti String         -- ^ 'JWT' ID
  | Unregistered String Value
  deriving (Show, Eq)
