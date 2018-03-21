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

This module provides functions which operate in any 'MonadIO' servant handler, as opposed to just 'Handler'.
They work best with handlers for which 'UnliftIO' (from "unliftio-core") is implemented.

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
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NamedFieldPuns #-}

module Servant.UcamWebauth
  ( authenticated
  , ucamWebauthCookie
  , ucamWebauthToken
  , ucamWebauthAuthenticate
  , ucamWebauthSettings
  , authURI
  , Cookied
  , servantMkJWT
  ) where

import "servant-raven" Servant.UcamWebauth.API
import "servant-raven" Servant.UcamWebauth.Settings
import "ucam-webauth" UcamWebauth
import "ucam-webauth-types" Data.ByteString.B64

import "base" Control.Monad.IO.Class
import "errors" Control.Error
import qualified "unliftio" UnliftIO.Exception as UIO

import "time" Data.Time

import "servant-server" Servant
import "servant-auth-server" Servant.Auth.Server
import "servant-auth-server" Servant.Auth.Server.SetCookieOrphan ()
import "jose" Crypto.JOSE.JWK (JWK)

import "aeson" Data.Aeson.Types hiding ((.=))

------------------------------------------------------------------------------
--
-- * Top level functions

-- | UcamWebauthInfo can be converted directly to a JWT.
instance ToJSON a => ToJWT (UcamWebauthInfo a)
-- | UcamWebauthInfo can be converted directly from a JWT.
instance FromJSON a => FromJWT (UcamWebauthInfo a)

-- | Wrap the provided handler function with authentication.
authenticated
    :: ThrowAll (handler protected)
    => (a -> handler protected)
    -> AuthResult a
    -> handler protected
authenticated f (Authenticated user) = f user
authenticated _ _ = throwAll err401

-- | If a GET request is made with no query parameters, redirect (303) to the authentication server.
--
-- If a GET request is made with the WLS-Response query parameter, try to
-- parse that parameter to a 'UcamWebauthInfo a', and then return that
-- parameter or throw a 401 error.
ucamWebauthAuthenticate
    :: forall a handler .
       ( ToJSON a
       , MonadIO handler
       )
    => SetWAA a
    -> Maybe (MaybeValidResponse a)
    -> handler (UcamWebauthInfo a)
ucamWebauthAuthenticate settings mresponse = do
        response <- UIO.fromEither . needToAuthenticate $ mresponse
        UIO.fromEitherIO . runExceptT . authError . authInfo settings $ response
    where
        needToAuthenticate = note err303 {errHeaders = ucamWebauthQuery settings}
        authError = withExceptT . const $ err401 { errBody = "Authentication error" }

-- | Here, if a GET request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function and then return the log in token.
-- Supply 'pure' to use 'UcamWebauthInfo a' as a token.
ucamWebauthToken
    :: forall a handler tok .
       ( ToJSON a
       , ToJWT tok
       , MonadIO handler
       )
    => (UcamWebauthInfo a -> handler tok)
    -> (Maybe UTCTime, JWK)
    -> SetWAA a
    -> Maybe (MaybeValidResponse a)
    -> handler (Base64UBSL tok)
ucamWebauthToken toToken jwkSet settings mresponse = do
        uwi <- ucamWebauthAuthenticate settings mresponse
        tok <- toToken uwi
        servantMkJWT jwkSet tok

-- | Here, if a request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function and then set the log in token
-- as a cookie. Supply 'pure' to use 'UcamWebauthInfo a' as a token.
ucamWebauthCookie
    :: forall a handler tok out .
       ( ToJSON a
       , ToJWT tok
       , MonadIO handler
       )
    => (UcamWebauthInfo a -> handler tok, tok -> handler out)
    -> JWK
    -> SetWAA a
    -> Maybe (MaybeValidResponse a)
    -> handler (Cookied out)
ucamWebauthCookie (toTok, fromTok) ky settings mresponse = let jwtCfg = defaultJWTSettings ky in do
        uwi <- ucamWebauthAuthenticate settings mresponse
        tok <- toTok uwi
        mApplyCookies <- liftIO $ acceptLogin cookieSettings jwtCfg tok
        out <- fromTok tok
        UIO.fromEither . note trans . fmap ($ out) $ mApplyCookies
    where
        trans = err401 { errBody = "Token error" }
        cookieSettings = defaultCookieSettings

servantMkJWT
  :: ( ToJWT tok
     , MonadIO handler
     )
  => (Maybe UTCTime, JWK) -> tok -> handler (Base64UBSL tok)
servantMkJWT (mexpires, ky) tok = UIO.fromEitherIO . runExceptT .
  bimapExceptT trans B64UL . ExceptT $ makeJWT tok jwtCfg mexpires
    where
        trans _ = err401 { errBody = "Token error" }
        jwtCfg = defaultJWTSettings ky
