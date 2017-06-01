{-|
Module      : Servant.UcamWebauth
Description : Authenticate using the Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

This module implements the client form of the University of Cambridge’s Ucam-Webauth protocol,
as in the link below. The protocol is a handshake between the

  [@WAA@], /i.e./ application wishing to authenticate (whatever uses this module!), and the
  [@WLS@], /i.e./ server which can authenticate the user

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

See the "Servant.Raven.Auth" module for a specific implementation, and
"Servant.Raven.Example" for an example.

It is necessary to store the relevant public keys, as described in the documentation
for 'readRSAKeyFile'.

-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeInType #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Servant.UcamWebauth
  ( authenticated
  , ucamWebAuthToken
  , ucamWebAuthenticate
  , ucamWebAuthSettings
  , uriByteString
  , networkUri
  , UB.URI
  -- , uriByteString'
  -- , networkUri'
  ) where

import "servant-raven" Servant.UcamWebauth.API
import "ucam-webauth" Network.Protocol.UcamWebauth
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data.Internal

import "base" Control.Applicative
import "base" Data.Kind
import "base" Data.Proxy
import "base" GHC.TypeLits hiding (Text)
import "reflection" Data.Reflection

import "errors" Control.Error
import "microlens-mtl" Lens.Micro.Mtl

import "text" Data.Text (Text)
import "text" Data.Text.Encoding
import qualified "text" Data.Text as T

import "time" Data.Time

import "servant" Servant.Utils.Links
import "servant-server" Servant
import "servant-auth-server" Servant.Auth.Server
import "servant-auth-server" Servant.Auth.Server.SetCookieOrphan ()
import "jose" Crypto.JOSE.JWK (JWK)

import "aeson" Data.Aeson.Types hiding ((.=))

import qualified "network-uri" Network.URI as NU
import qualified "uri-bytestring" URI.ByteString as UB

import qualified "bytestring" Data.ByteString.Char8 as B8

------------------------------------------------------------------------------
--
-- * Top level functions

-- | Base 64 (URL) encoded 'ByteString's should be serializable as 'OctetStream's.
-- They are already serializable as 'JSON' thanks to the ToJson instance.
instance MimeRender OctetStream Base64UBSL where
    mimeRender _ = unB64UL

-- TODO Make safe
instance MimeUnrender OctetStream Base64UBSL where
    mimeUnrender _ = pure . B64UL

-- | UcamWebauthInfo can be converted directly to a JWT.
instance ToJSON a => ToJWT (UcamWebauthInfo a)
-- | UcamWebauthInfo can be converted directly from a JWT.
instance FromJSON a => FromJWT (UcamWebauthInfo a)

-- | Wrap the provided handler function with authentication.
authenticated
    :: ThrowAll (Handler protected)
    => (a -> Handler protected)
    -> AuthResult a
    -> Handler protected
authenticated f (Authenticated user) = f user
authenticated _ _ = throwAll err401

-- | If a GET request is made with no query parameters, redirect (303) to the authentication server.
--
-- If a GET request is made with the WLS-Response query parameter, try to
-- parse that parameter to a 'UcamWebauthInfo a', and then return that
-- parameter or throw a 401 error.
ucamWebAuthenticate
    :: forall a. ToJSON a
    => SetWAA a
    -> Maybe (SignedAuthResponse 'MaybeValid a)
    -> Handler (UcamWebauthInfo a)
ucamWebAuthenticate settings mresponse = do
        response <- Handler . needToAuthenticate . liftMaybe $ mresponse
        Handler . authError . authInfo settings $ response
    where
        needToAuthenticate = noteT err303 {errHeaders = [ucamWebauthQuery settings]}
        authError = withExceptT . const $ err401 { errBody = "Authentication error" }

-- | Here, if a GET request is made with a valid WLS-Response query parameter, return the
-- 'UcamWebauthInfo a' as a log in token.
ucamWebAuthToken
    :: forall a. ToJSON a
    => SetWAA a
    -> Maybe UTCTime
    -> JWK
    -> Maybe (SignedAuthResponse 'MaybeValid a)
    -> Handler Base64UBSL
ucamWebAuthToken settings mexpires ky mresponse = let jwtCfg = defaultJWTSettings ky in do
        uwi <- ucamWebAuthenticate settings mresponse
        Handler . bimapExceptT trans B64UL . ExceptT $ makeJWT uwi jwtCfg mexpires
    where
        trans _ = err401 { errBody = "Token error" }

-- | The default settings for UcamWebauth should generate the application
-- link from the api type.
--
-- This must be reified with a 'Network.URI.URIAuth' value corresponding to
-- the base url of the api.
ucamWebAuthSettings
    :: forall baseurl (api :: Type) (e :: Type) (route :: Symbol) token a endpoint .
       ( IsElem endpoint api
       , HasLink endpoint
       , endpoint ~ Unqueried e
       , e ~ UcamWebAuthToken route token a
       , Reifies baseurl UB.URI
       )
    => SetWAA a
ucamWebAuthSettings = do
        wSet . applicationUrl .= authLink
    where
        authLink :: Text
        authLink = authURI . linkURI $ safeLink (Proxy @api) (Proxy @endpoint)

        authURI :: URI -> Text
        authURI uri = "" `fromMaybe` do
            relUri <- hush . UB.parseRelativeRef UB.laxURIParserOptions . B8.pack . show $ uri
            pure . decodeUtf8 . UB.serializeURIRef' $ UB.uriScheme baseUri `UB.toAbsolute` relUri

        baseUri :: UB.URI
        baseUri = reflect @baseurl Proxy

liftMaybe :: Alternative f => Maybe a -> f a
liftMaybe = maybe empty pure

uriByteString :: NU.URI -> Maybe (UB.URIRef UB.Absolute)
uriByteString = hush . UB.parseURI UB.laxURIParserOptions . B8.pack . flip (NU.uriToString id) ""

networkUri :: UB.URIRef UB.Absolute -> Maybe NU.URI
networkUri = NU.parseURI . B8.unpack . UB.serializeURIRef'

{-
 -uriByteString' :: NU.URI -> UB.URIRef UB.Absolute
 -uriByteString' NU.URI{..} = UB.URI{..}
 -    where
 -        uriScheme = Scheme . B8.pack $ NU.uriScheme
 -        uriAuthority = do
 -            NU.URIAuth{..} <- NU.uriAuthority
 -            let authorityUserInfo = uriUserInfo
 -                authorityHost = uriRegName
 -                authorityPort = uriPort
 -            pure UB.Authority{..}
 -        uriPath = B8.pack NU.uriPath
 -        uriQuery =
 -        uriFragment = pure . B8.pack $ NU.uriFragment
 -}
