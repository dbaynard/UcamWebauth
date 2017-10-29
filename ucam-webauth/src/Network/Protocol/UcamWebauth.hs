{-|
Module      : Network.Protocol.UcamWebauth
Description : The Ucam-Webauth protocol, from the University of Cambridge
Maintainer  : David Baynard <davidbaynard@gmail.com>

Key parts of the implementation of the protocol itself.

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}

module Network.Protocol.UcamWebauth
  ( module X

  -- Parser
  , ucamResponseParser

  , authInfo
  , maybeAuthInfo
  , authCode

  , validateAuthResponse
  ) where

-- Prelude
import Network.Protocol.UcamWebauth.Internal

import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data as X
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data.Internal

import Network.Protocol.UcamWebauth.Parser

import "base" Data.Coerce
import "base" Control.Monad.IO.Class
import "base" Control.Applicative
import "base" Control.Monad
import "base" Data.Semigroup
import "base" Data.Bifunctor

import "mtl" Control.Monad.Except

import "containers" Data.Map.Strict (Map)
import qualified "containers" Data.Map.Strict as MapS

import "microlens" Lens.Micro
import "microlens-mtl" Lens.Micro.Mtl

import "errors" Control.Error hiding (catMaybes)

import "base" System.IO (withFile, IOMode(..))

-- Parsing
import "attoparsec" Data.Attoparsec.ByteString.Char8 hiding (count, take)

-- HTTP protocol
import "http-api-data" Web.HttpApiData

-- Character encoding
import "bytestring" Data.ByteString (ByteString)
import "text" Data.Text (Text)
import "text" Data.Text.Encoding hiding (decodeASCII)
import qualified "text" Data.Text as T
import qualified "bytestring" Data.ByteString.Char8 as B

-- Time
import "time" Data.Time (diffUTCTime, getCurrentTime)

-- JSON (Aeson)
import "aeson" Data.Aeson (FromJSON)

-- Crypto
import "cryptonite" Crypto.PubKey.RSA.Types
import "cryptonite" Crypto.PubKey.RSA.PKCS15
import "cryptonite" Crypto.Hash.Algorithms
import "x509" Data.X509
import "pem" Data.PEM

------------------------------------------------------------------------------
-- * Top level functions

{-|
  If the supplied response is valid and corresponds to the settigns, return a 'UcamWebauthInfo' value.

-}
authInfo
    :: (MonadIO m, MonadPlus m, MonadError Text m)
    => SetWAA a
    -> SignedAuthResponse 'MaybeValid a
    -> m (UcamWebauthInfo a)
authInfo waa = getAuthInfo <=< validateAuthResponse waa

{-|
  'maybeAuthInfo' takes the 'AuthRequest' from its environment, and a 'ByteString' containing the @WLS@
  response, and if the response is valid, returns a 'UcamWebauthInfo' value.

  TODO When the errors returned can be usefully used, ensure this correctly returns a lifted
  'Either b (UcamWebauthInfo a)' response.
-}
maybeAuthInfo
    :: (FromJSON a, MonadIO m, MonadPlus m, MonadError Text m)
    => SetWAA a
    -> ByteString
    -> m (UcamWebauthInfo a)
maybeAuthInfo waa = getAuthInfo <=< maybeAuthCode waa

{-|
  A helper function to parse and validate a response from a @WLS@.
-}
maybeAuthCode
    :: (FromJSON a, MonadIO m, MonadPlus m, MonadError Text m)
    => SetWAA a
    -> ByteString
    -> m (SignedAuthResponse 'Valid a)
maybeAuthCode waa = validateAuthResponse waa <=< authCode

{-|
  Parse the response from a @WLS@.
-}
authCode
    :: (FromJSON a, MonadPlus m)
    => ByteString
    -> m (SignedAuthResponse 'MaybeValid a)
authCode = liftMaybe . maybeResult . flip feed "" . parse ucamResponseParser

-- | Parse a not-yet-validated 'SignedAuthResponse' from a form response.
--
-- The orphan instance is necessary as this requires the parser defined in
-- this package.
instance FromJSON a => FromHttpApiData (SignedAuthResponse 'MaybeValid a) where
    parseQueryParam = first T.pack . parseOnly ucamResponseParser . encodeUtf8

------------------------------------------------------------------------------
-- * Validation

guardE
    :: forall e m . (MonadError e m, Alternative m)
    => e -> Bool -> m ()
guardE e boolean = guard boolean <|> throwError e

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
validateAuthResponse
    :: forall a m . (MonadIO m, MonadPlus m, MonadError Text m)
    => SetWAA a
    -> SignedAuthResponse 'MaybeValid a
    -> m (SignedAuthResponse 'Valid a)
validateAuthResponse waa sar = do
        guardE "Key invalid" .
            validateKid waa =<< liftMaybe (sar ^. ucamAKid)
        guardE "Signature invalid" <=<
            validateSig waa $ sar
        guardE "Issue time invalid" <=<
            validateIssueTime waa $ sar ^. ucamAResponse
        guardE "Url does not match transmittion" .
            validateUrl waa $ sar ^. ucamAResponse
        guardE "Authentication type invalid" <=<
            validateAuthTypes waa $ sar ^. ucamAResponse
        return . makeValid $ sar
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
validateSig
    :: (MonadPlus m, MonadIO m)
    => SetWAA a
    -> SignedAuthResponse 'MaybeValid a
    -> m Bool
validateSig (configWAA -> waa) = validateSigKey (readRSAKeyFile $ waa ^. wSet . importedKeys)

decodeRSAPubKey
    :: ByteString      -- ^ The data representing a public key as PEM.
    -> Maybe PublicKey -- ^ @'Just' 'PublicKey'@ if RSA, 'Nothing' otherwise.
decodeRSAPubKey = hush . f

    where
        f :: ByteString -> Either String PublicKey
        f = getRSAKey . certPubKey . getCertificate
            <=< decodeSignedCertificate . pemContent
            <=< headErr "Empty list"
            <=< pemParseBS

        getRSAKey :: Alternative f => PubKey -> f PublicKey
        getRSAKey (PubKeyRSA x) = pure x
        getRSAKey _ = empty

{-|
  This assumes keys are PEM self-signed certificates in the ‘static’ directory, named

  @pubkey/key/.crt@

  where @/key/@ should be replaced by the 'KeyID' /e.g./ @pubkey2.crt@
-}
readRSAKeyFile
    :: (MonadIO m, Alternative m)
    => Map KeyID ByteString
    -> KeyID
    -> m PublicKey
readRSAKeyFile keymap key = case key `MapS.lookup` keymap of
    Just bs -> liftMaybe . decodeRSAPubKey $ bs
    Nothing -> let file = "static/pubkey" <> (B.unpack . unKeyID) key <> ".crt" in
        liftMaybe <=< liftIO . withFile file ReadMode
        $ pure . decodeRSAPubKey <=< B.hGetContents

validateSigKey
    :: MonadPlus m
    => (KeyID
    -> m PublicKey)                     -- ^ Get an RSA 'PublicKey' from somewhere, with the possibility of failing.
    -> SignedAuthResponse 'MaybeValid a
    -> m Bool                           -- ^ 'True' for a verified signature, 'False' for a verified invalid signature, and 'mzero' for an inability to validate
validateSigKey importKey sar =
        pure . rsaValidate <=< importKey <=< liftMaybe $ sar ^. ucamAKid
    where
        rsaValidate :: PublicKey -> Bool
        rsaValidate key = verify (Just SHA1) key message signature
        message :: ByteString
        message = sar ^. ucamAToSign
        signature :: ByteString
        signature = maybe mempty decodeUcamB64 . view ucamASig $ sar

------------------------------------------------------------------------------
-- ** Issue time

{-|
  Validate the time of issue is within 'syncTimeOut' of the current time.

  TODO Uses 'getCurrentTime'. There may be a better implementation.
-}
validateIssueTime
    :: (MonadIO m)
    => SetWAA a
    -> AuthResponse a
    -> m Bool
validateIssueTime (configWAA -> waa) ar =
    (waa ^. wSet . syncTimeOut >) . flip diffUTCTime (ar ^. ucamAIssue)
    <$> liftIO getCurrentTime

------------------------------------------------------------------------------
-- ** Url

{-|
  Check the url parameter matches that sent in the 'AuthRequest'
-}
validateUrl
    :: SetWAA a
    -> AuthResponse a
    -> Bool
validateUrl (configWAA -> waa) =
    (== waa ^. aReq . ucamQUrl) . view ucamAUrl

------------------------------------------------------------------------------
-- ** Authentication type

{-|
  Check the authentication type matches that sent.

  * If the iact variable is Yes, only return 'True' if the aauth value is acceptable.
  * If the iact variable is No, only return 'True' if sso contains a value that is acceptable.
  * If the iact variable is unset, return 'True' if there is an acceptable value in either field.
-}
validateAuthTypes
    :: forall a f . (Alternative f)
    => SetWAA a
    -> AuthResponse a
    -> f Bool
validateAuthTypes (configWAA -> waa) ar =
        maybe validateAnyAuth validateSpecificAuth $ waa ^. wSet . needReauthentication

    where
        isAcceptableAuth :: AuthType -> Bool
        isAcceptableAuth = flip elem $ waa ^. wSet . authAccepted

        anyAuth :: Maybe AuthType -> Maybe [AuthType] -> Bool
        anyAuth Nothing (Just x) = any isAcceptableAuth x
        anyAuth (Just x) Nothing = isAcceptableAuth x
        anyAuth _ _ = False

        validateAnyAuth :: f Bool
        validateAnyAuth = pure $ (ar ^. ucamAAuth) `anyAuth` (ar ^. ucamASso)

        validateSpecificAuth :: YesNo -> f Bool
        validateSpecificAuth Yes = isAcceptableAuth <$> liftMaybe (ar ^. ucamAAuth)
        validateSpecificAuth _ = any isAcceptableAuth <$> liftMaybe (ar ^. ucamASso)