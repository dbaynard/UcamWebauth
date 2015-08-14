{-|
Module      : Network.Protocol.UcamWebauth
Description : The Ucam-Webauth protocol, from the University of Cambridge
Maintainer  : David Baynard <davidbaynard@gmail.com>

Key parts of the implementation of the protocol itself.

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

-}

module Network.Protocol.UcamWebauth (
    module Network.Protocol.UcamWebauth
  , module Network.Protocol.UcamWebauth.Data
  , module Network.Protocol.UcamWebauth.Internal
  , module Network.Protocol.UcamWebauth.Parser
)   where

-- Prelude
import ClassyPrelude

import Network.Protocol.UcamWebauth.Internal
import Network.Protocol.UcamWebauth.Data
import Network.Protocol.UcamWebauth.Parser

import Data.Coerce

import Control.Error hiding (catMaybes)

import System.IO (withFile, IOMode(..))

-- Parsing
import Data.Attoparsec.ByteString.Char8 hiding (count, take)

-- HTTP protocol
import Network.HTTP.Types

-- Settings
import Data.Settings.Internal
import Data.Lens.Internal

-- Character encoding
import qualified Data.ByteString.Base64.Lazy as L

import qualified Data.Text as T
import qualified Data.ByteString.Char8 as B

-- ByteString building
import Blaze.ByteString.Builder hiding (Builder)

-- Time
import Data.Time (diffUTCTime)

-- JSON (Aeson)
import Data.Aeson (ToJSON, FromJSON)
import qualified Data.Aeson as A

-- Crypto
import Crypto.PubKey.RSA.Types
import Crypto.PubKey.RSA.PKCS15
import Crypto.Hash.Algorithms
import Data.X509
import Data.PEM

------------------------------------------------------------------------------
-- * Top level functions

{-|
  'maybeAuthInfo' takes the 'AuthRequest' from its environment, and a 'ByteString' containing the @WLS@
  response, and if the response is valid, returns a 'UcamWebauthInfo' value.

  TODO When the errors returned can be usefully used, ensure this correctly returns a lifted
  'Either b (UcamWebauthInfo a)' response.
-}
maybeAuthInfo :: (FromJSON a, MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m) => SetWAA -> ByteString -> m (UcamWebauthInfo a)
maybeAuthInfo mkConfig = getAuthInfo <=< maybeAuthCode mkConfig

{-|
  A helper function to parse and validate a response from a @WLS@.
-}
maybeAuthCode :: (FromJSON a, MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m) => SetWAA -> ByteString -> m (SignedAuthResponse 'Valid a)
maybeAuthCode mkConfig = validateAuthResponse mkConfig <=< authCode

{-|
  Parse the response from a @WLS@.
-}
authCode :: (FromJSON a, MonadIO m, MonadPlus m) => ByteString -> m (SignedAuthResponse 'MaybeValid a)
authCode = liftMaybe . maybeResult . flip feed "" . parse ucamResponseParser

------------------------------------------------------------------------------
-- * Printing

{-|
  Build a request header to send to the @WLS@, using an 'AuthRequest'
-}
ucamWebauthQuery :: ToJSON a => BlazeBuilder -- ^ The url of the @WLS@ api /e.g./ <https://raven.cam.ac.uk/auth/authenticate.html>
                             -> AuthRequest a
                             -> Header
ucamWebauthQuery url AuthRequest{..} = (hLocation, toByteString $ url <> theQuery)
    where
        theQuery :: BlazeBuilder
        theQuery = renderQueryBuilder True $ strictQs <> textQs <> lazyQs
        strictQs :: Query
        strictQs = toQuery [
                   ("ver", pure . textWLSVersion $ _ucamQVer) :: (Text, Maybe ByteString)
                 , ("desc", encodeUtf8 . decodeASCII <$> _ucamQDesc)
                 , ("iact", displayYesNoS <$> _ucamQIact)
                 , ("fail", displayYesOnlyS <$> _ucamQFail)
                 ]
        textQs :: Query
        textQs = toQuery [
                   ("url" , pure _ucamQUrl) :: (Text, Maybe Text)
                 , ("date", unUcamTime . ucamTime <$> _ucamQDate)
                 , ("aauth", T.intercalate "," . fmap displayAuthType <$> _ucamQAauth)
                 , ("msg", _ucamQMsg)
                 ]
        lazyQs :: Query
        lazyQs = toQuery [
                   ("params", L.encode . A.encode <$> _ucamQParams) :: (Text, Maybe LByteString)
                 ]

------------------------------------------------------------------------------
-- * 'WAASettings'

{-|
  Type synonym for WAASettings settings type.
-}
type SetWAA = Mod WAASettings

{-|
  The default @WAA@ settings. To accept the defaults, use

  > configWAA def

  or

  > configWAA . return $ ()

  To modify settings, use the provided lenses.
-}
configWAA :: SetWAA -> WAASettings
configWAA = config MakeWAASettings {
                   _authAccepted = [Pwd]
                 , _needReauthentication = Nothing
                 , _syncTimeOut = 40
                 , _validKids = empty
                 , _recentTime = UTCTime (ModifiedJulianDay 0) 0
                 , _applicationUrl = mempty
                 }

{-|
  To access settings, use the lenses. In the default case,

  @viewConfigWAA /lens/ def@
-}
viewConfigWAA :: WAASettings :~> a -> SetWAA -> a
{-# INLINE viewConfigWAA #-}
viewConfigWAA lens = view lens . configWAA

------------------------------------------------------------------------------
-- * Validation

{-|
  Validate the Authentication Response

  1. Validate the key id
  2. Validate the cryptographic signature against the relevant key
  3. Validate the issue time
  4. Validate the url is the same as that transmitted
  5. Validate the auth and sso values are valid

  The protocol requires a valid input, but 'ucamResponseParser' holds all the relevant logic
  as the only way to produce a 'SignedAuthResponse' is with the parser.

  This is the only way to produce a 'Valid' 'SignedAuthResponse', and therefore an 'AuthInfo'.
-}
validateAuthResponse :: forall a m . (MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m)
                     => SetWAA
                     -> SignedAuthResponse 'MaybeValid a
                     -> m (SignedAuthResponse 'Valid a)
validateAuthResponse mkConfig x@SignedAuthResponse{..} = do
        guard . validateKid mkConfig =<< liftMaybe _ucamAKid
        guard <=< validateSig $ x
        guard <=< validateIssueTime mkConfig $ _ucamAResponse
        guard <=< validateUrl $ _ucamAResponse
        guard <=< validateAuthTypes mkConfig $ _ucamAResponse
        return . makeValid $ x
        where
            makeValid :: SignedAuthResponse 'MaybeValid a -> SignedAuthResponse 'Valid a
            makeValid = coerce

------------------------------------------------------------------------------
-- ** Key ID

{-|
  Check the kid is valid
-}
validateKid :: SetWAA -> KeyID -> Bool
validateKid = flip elem . viewConfigWAA validKids

------------------------------------------------------------------------------
-- ** Signature

{-|
  Validate the signature, getting the key using 'readRSAKeyFile'
-}
validateSig :: (MonadPlus m, MonadIO m) => SignedAuthResponse 'MaybeValid a -> m Bool
validateSig = validateSigKey readRSAKeyFile 

decodeRSAPubKey :: ByteString -- ^ The data representing a public key as PEM.
             -> Maybe PublicKey -- ^ @'Just' 'PublicKey'@ if RSA, 'Nothing' otherwise.
decodeRSAPubKey = hush . f
    where
        f :: ByteString -> Either String PublicKey
        f = getRSAKey . certPubKey . getCertificate <=< decodeSignedCertificate . pemContent <=< headErr "Empty list" <=< pemParseBS
        getRSAKey :: Alternative f => PubKey -> f PublicKey
        getRSAKey (PubKeyRSA x) = pure x
        getRSAKey _ = empty

{-|
  This assumes keys are PEM self-signed certificates in the ‘static’ directory, named

  @pubkey/key/.crt@

  where @/key/@ should be replaced by the 'KeyID' /e.g./ @pubkey2.crt@
-}
readRSAKeyFile :: (MonadIO m, Alternative m) => KeyID
                                             -> m PublicKey
readRSAKeyFile key = liftMaybe <=< liftIO . withFile ("static/pubkey" <> (B.unpack . unKeyID) key <> ".crt") ReadMode $ 
        pure . decodeRSAPubKey <=< hGetContents

validateSigKey :: MonadPlus m
               => (KeyID -> m PublicKey) -- ^ Get an RSA 'PublicKey' from somewhere, with the possibility of failing.
               -> SignedAuthResponse 'MaybeValid a
               -> m Bool -- ^ 'True' for a verified signature, 'False' for a verified invalid signature, and 'mzero' for an inability to validate
validateSigKey importKey SignedAuthResponse{..} = pure . rsaValidate =<< importKey =<< liftMaybe _ucamAKid
    where
        rsaValidate :: PublicKey -> Bool
        rsaValidate key = verify (Just SHA1) key message signature
        message :: ByteString
        message = _ucamAToSign
        signature :: ByteString
        signature = maybe mempty decodeUcamB64 _ucamASig

------------------------------------------------------------------------------
-- ** Issue time

{-|
  Validate the time of issue is within 'syncTimeOut' of the current time.

  TODO Uses 'getCurrentTime'. There may be a better implementation.
-}
validateIssueTime :: (MonadIO m) => SetWAA -> AuthResponse a -> m Bool
validateIssueTime mkConfig AuthResponse{..} = (viewConfigWAA syncTimeOut mkConfig >) . flip diffUTCTime _ucamAIssue <$> liftIO getCurrentTime

------------------------------------------------------------------------------
-- ** Url

{-|
  Check the url parameter matches that sent in the 'AuthRequest'
-}
validateUrl :: (MonadReader (AuthRequest a) m) => AuthResponse a -> m Bool
validateUrl AuthResponse{..} = (==) _ucamAUrl . _ucamQUrl <$> ask

------------------------------------------------------------------------------
-- ** Authentication type

{-|
  Check the authentication type matches that sent.

  * If the iact variable is Yes, only return 'True' if the aauth value is acceptable.
  * If the iact variable is No, only return 'True' if sso contains a value that is acceptable.
  * If the iact variable is unset, return 'True' if there is an acceptable value in either field.
-}
validateAuthTypes :: forall a f . (Alternative f) => SetWAA -> AuthResponse a -> f Bool
validateAuthTypes mkConfig AuthResponse{..} = maybe validateAnyAuth validateSpecificAuth . viewConfigWAA needReauthentication $ mkConfig
    where
        isAcceptableAuth :: AuthType -> Bool
        isAcceptableAuth = flip elem . viewConfigWAA authAccepted $ mkConfig
        anyAuth :: Maybe AuthType -> Maybe [AuthType] -> Bool
        anyAuth Nothing (Just x) = any isAcceptableAuth x
        anyAuth (Just x) Nothing = isAcceptableAuth x
        anyAuth _ _ = False
        validateAnyAuth :: f Bool
        validateAnyAuth = pure $ anyAuth _ucamAAuth _ucamASso
        validateSpecificAuth :: YesNo -> f Bool
        validateSpecificAuth Yes = isAcceptableAuth <$> liftMaybe _ucamAAuth
        validateSpecificAuth _ = any isAcceptableAuth <$> liftMaybe _ucamASso
