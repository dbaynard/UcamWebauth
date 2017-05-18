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

module Servant.UcamWebauth (
    module Servant.UcamWebauth
  , module X
)   where

-- Prelude
import "Ucam-Webauth" Network.Protocol.UcamWebauth as X

import "base" Data.Kind
import "base" GHC.TypeLits

import "errors" Control.Error
import "microlens-mtl" Lens.Micro.Mtl
import "reflection" Data.Reflection

import "text" Data.Text (Text)
import qualified "text" Data.Text as T

import "time" Data.Time

import "servant" Servant.Utils.Links
import "servant-server" Servant
import "servant-auth-server" Servant.Auth.Server
import "servant-auth-server" Servant.Auth.Server.SetCookieOrphan ()
import "jose" Crypto.JOSE.JWK (JWK)

import "aeson" Data.Aeson.Types hiding ((.=))

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

-- | Remove the query parameters from a type for easier safe-link making
-- TODO Make injective?
type family Unqueried a = p

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthenticate route a
    = route :> QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[JSON] (UcamWebauthInfo a)

type instance Unqueried (UcamWebAuthenticate route a) = route :> Get '[JSON] (UcamWebauthInfo a)

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

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthToken route token a
    = route :> QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[OctetStream] token

type instance Unqueried (UcamWebAuthToken route token a) = route :> Get '[OctetStream] token

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
       , Reifies baseurl URI
       )
    => SetWAA a
ucamWebAuthSettings = do
        wSet . applicationUrl .= authLink
    where
        authLink :: Text
        authLink = authURI . linkURI $ safeLink (Proxy @api) (Proxy @endpoint)
        authURI :: URI -> Text
        authURI URI{..} = T.pack . show $ uri {uriPath='/':uriPath, uriQuery, uriFragment}
        uri :: URI
        uri = reflect @baseurl Proxy

