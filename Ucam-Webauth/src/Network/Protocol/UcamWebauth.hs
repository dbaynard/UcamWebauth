{-|
Module      : Network.Protocol.UcamWebauth
Description : The Ucam-Webauth protocol, from the University of Cambridge
Maintainer  : David Baynard <davidbaynard@gmail.com>

Key parts of the implementation of the protocol itself.

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

-}

{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.Protocol.UcamWebauth (
    module Network.Protocol.UcamWebauth
  , module X
)   where

-- Prelude

import Network.Protocol.UcamWebauth.Internal as X
import Network.Protocol.UcamWebauth.Data as X
import Network.Protocol.UcamWebauth.Parser as X

import "base" Data.Coerce
import "base" Control.Monad.IO.Class
import "base" Control.Applicative
import "base" Control.Monad
import "base" Data.Semigroup

import "microlens" Lens.Micro
import "microlens-mtl" Lens.Micro.Mtl

import "errors" Control.Error hiding (catMaybes)

import "base" System.IO (withFile, IOMode(..))

-- Parsing
import "attoparsec" Data.Attoparsec.ByteString.Char8 hiding (count, take)

-- HTTP protocol
import "http-types" Network.HTTP.Types

-- Settings
import Data.Settings.Internal

-- Character encoding
import qualified "base64-bytestring" Data.ByteString.Base64.Lazy as L

import "bytestring" Data.ByteString (ByteString)
import qualified "bytestring" Data.ByteString.Lazy as BSL
import "text" Data.Text (Text)
import "text" Data.Text.Encoding hiding (decodeASCII)
import qualified "text" Data.Text as T
import qualified "bytestring" Data.ByteString.Char8 as B

-- ByteString building
import "bytestring" Data.ByteString.Builder

-- Time
import "time" Data.Time (diffUTCTime, getCurrentTime)

-- JSON (Aeson)
import "aeson" Data.Aeson (ToJSON, FromJSON)
import qualified "aeson" Data.Aeson as A

-- Crypto
import "cryptonite" Crypto.PubKey.RSA.Types
import "cryptonite" Crypto.PubKey.RSA.PKCS15
import "cryptonite" Crypto.Hash.Algorithms
import "x509" Data.X509
import "pem" Data.PEM

type LByteString = BSL.ByteString

------------------------------------------------------------------------------
-- * Top level functions

{-|
  'maybeAuthInfo' takes the 'AuthRequest' from its environment, and a 'ByteString' containing the @WLS@
  response, and if the response is valid, returns a 'UcamWebauthInfo' value.

  TODO When the errors returned can be usefully used, ensure this correctly returns a lifted
  'Either b (UcamWebauthInfo a)' response.
-}
maybeAuthInfo :: (FromJSON a, MonadIO m, MonadPlus m) => SetWAA a -> ByteString -> m (UcamWebauthInfo a)
maybeAuthInfo waa = getAuthInfo <=< maybeAuthCode waa

{-|
  A helper function to parse and validate a response from a @WLS@.
-}
maybeAuthCode :: (FromJSON a, MonadIO m, MonadPlus m) => SetWAA a -> ByteString -> m (SignedAuthResponse 'Valid a)
maybeAuthCode waa = validateAuthResponse waa <=< authCode

{-|
  Parse the response from a @WLS@.
-}
authCode :: (FromJSON a, MonadPlus m) => ByteString -> m (SignedAuthResponse 'MaybeValid a)
authCode = liftMaybe . maybeResult . flip feed "" . parse ucamResponseParser

------------------------------------------------------------------------------
-- * Printing

{-|
  Build a request header to send to the @WLS@, using an 'AuthRequest'
-}
ucamWebauthQuery :: ToJSON a => SetWAA a
                             -> Header
ucamWebauthQuery (configWAA -> waa) = (hLocation,) . toByteString $ baseUrl waa <> theQuery
    where
        baseUrl :: WAAState a -> Builder
        baseUrl = encodeUtf8Builder . view (wSet . wlsUrl)
        theQuery :: Builder
        theQuery = renderQueryBuilder True $ strictQs <> textQs <> lazyQs
        strictQs :: Query
        strictQs = toQuery [
                   ("ver", pure . textWLSVersion $ waa ^. aReq . ucamQVer) :: (Text, Maybe ByteString)
                 , ("desc", encodeUtf8 . decodeASCII <$> waa ^. aReq . ucamQDesc)
                 , ("iact", displayYesNoS <$> waa ^. aReq . ucamQIact)
                 , ("fail", displayYesOnlyS <$> waa ^. aReq . ucamQFail)
                 ]
        textQs :: Query
        textQs = toQuery [
                   ("url" , pure $ waa ^. aReq . ucamQUrl) :: (Text, Maybe Text)
                 , ("date", unUcamTime . ucamTime <$> waa ^. aReq . ucamQDate)
                 , ("aauth", T.intercalate "," . fmap displayAuthType <$> waa ^. aReq . ucamQAauth)
                 , ("msg", waa ^. aReq . ucamQMsg)
                 ]
        lazyQs :: Query
        lazyQs = toQuery [
                   ("params", L.encode . A.encode <$> waa ^. aReq . ucamQParams) :: (Text, Maybe LByteString)
                 ]
        toByteString = BSL.toStrict . toLazyByteString

------------------------------------------------------------------------------
-- * 'WAASettings'

{-|
  Type synonym for WAASettings settings type.
-}
type SetWAA a = Mod (WAAState a)

{-|
  The default @WAA@ settings. To accept the defaults, use

  > configWAA def

  or

  > configWAA . return $ ()

  To modify settings, use the provided lenses.

  TODO 'configWAA' should not be exported. Instead, all functions requiring settings
  should use this function in a view pattern.
-}
configWAA :: SetWAA a -> WAAState a
configWAA = config MakeWAAState {
                   _wSet = settings
                 , _aReq = request
                 }
    where
        settings :: WAASettings
        settings = MakeWAASettings {
                           _authAccepted = [Pwd]
                         , _needReauthentication = Nothing
                         , _syncTimeOut = 40
                         , _validKids = empty
                         , _recentTime = error "You must assign a time to check the issue time of a response is valid."
                         , _applicationUrl = mempty
                         , _wlsUrl = error "You must enter a URL for the authentication server."
                         }
        request :: AuthRequest a
        request = MakeAuthRequest {
                           _ucamQVer = WLS3
                         , _ucamQUrl = error "You must enter a URL for the application wishing to authenticate the user."
                         , _ucamQDesc = pure "This should be the ASCII description of the application requesting authentication"
                         , _ucamQAauth = empty
                         , _ucamQIact = empty
                         , _ucamQMsg = pure "This should be the reason authentication is requested."
                         , _ucamQParams = empty
                         , _ucamQDate = empty
                         , _ucamQFail = pure YesOnly
                         }

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
validateAuthResponse :: forall a m . (MonadIO m, MonadPlus m)
                     => SetWAA a
                     -> SignedAuthResponse 'MaybeValid a
                     -> m (SignedAuthResponse 'Valid a)
validateAuthResponse waa x@SignedAuthResponse{..} = do
        guard . validateKid waa =<< liftMaybe _ucamAKid
        guard <=< validateSig $ x
        guard <=< validateIssueTime waa $ _ucamAResponse
        guard . validateUrl waa $ _ucamAResponse
        guard <=< validateAuthTypes waa $ _ucamAResponse
        return . makeValid $ x
        where
            makeValid :: SignedAuthResponse 'MaybeValid a -> SignedAuthResponse 'Valid a
            makeValid = coerce

------------------------------------------------------------------------------
-- ** Key ID

{-|
  Check the kid is valid
-}
validateKid :: SetWAA a -> KeyID -> Bool
validateKid = flip elem . view (wSet . validKids) . configWAA

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
        pure . decodeRSAPubKey <=< B.hGetContents

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
validateIssueTime :: (MonadIO m) => SetWAA a -> AuthResponse a -> m Bool
validateIssueTime (configWAA -> waa) AuthResponse{..} = (waa ^. wSet . syncTimeOut >) . flip diffUTCTime _ucamAIssue <$> liftIO getCurrentTime

------------------------------------------------------------------------------
-- ** Url

{-|
  Check the url parameter matches that sent in the 'AuthRequest'
-}
validateUrl :: SetWAA a -> AuthResponse a -> Bool
validateUrl (configWAA -> waa) = (== waa ^. aReq . ucamQUrl) . _ucamAUrl

------------------------------------------------------------------------------
-- ** Authentication type

{-|
  Check the authentication type matches that sent.

  * If the iact variable is Yes, only return 'True' if the aauth value is acceptable.
  * If the iact variable is No, only return 'True' if sso contains a value that is acceptable.
  * If the iact variable is unset, return 'True' if there is an acceptable value in either field.
-}
validateAuthTypes :: forall a f . (Alternative f) => SetWAA a -> AuthResponse a -> f Bool
validateAuthTypes (configWAA -> waa) AuthResponse{..} = maybe validateAnyAuth validateSpecificAuth $ waa ^. wSet . needReauthentication
    where
        isAcceptableAuth :: AuthType -> Bool
        isAcceptableAuth = flip elem $ waa ^. wSet . authAccepted
        anyAuth :: Maybe AuthType -> Maybe [AuthType] -> Bool
        anyAuth Nothing (Just x) = any isAcceptableAuth x
        anyAuth (Just x) Nothing = isAcceptableAuth x
        anyAuth _ _ = False
        validateAnyAuth :: f Bool
        validateAnyAuth = pure $ anyAuth _ucamAAuth _ucamASso
        validateSpecificAuth :: YesNo -> f Bool
        validateSpecificAuth Yes = isAcceptableAuth <$> liftMaybe _ucamAAuth
        validateSpecificAuth _ = any isAcceptableAuth <$> liftMaybe _ucamASso
