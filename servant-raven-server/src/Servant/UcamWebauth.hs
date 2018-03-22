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
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE RankNTypes #-}

module Servant.UcamWebauth
  ( ucamWebauthCookie
  , ucamWebauthToken
  , ucamWebauthAuthenticate
  , ucamWebauthSettings
  , authURI
  , Cookied
  , servantMkJWT
  -- Authentication arguments
  , AuthenticationArgs
  , authenticationArgs
  , authJWK
  , authTokCreate
  , authTokUse
  , authWAASettings
  , authExpires
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
import "microlens" Lens.Micro
import "microlens-mtl" Lens.Micro.Mtl
import "mtl" Control.Monad.State

------------------------------------------------------------------------------
--
-- * Top level functions

-- | UcamWebauthInfo can be converted directly to a JWT.
instance ToJSON a => ToJWT (UcamWebauthInfo a)
-- | UcamWebauthInfo can be converted directly from a JWT.
instance FromJSON a => FromJWT (UcamWebauthInfo a)

--------------------------------------------------
-- * Authentication arguments
--------------------------------------------------

data AuthenticationArgs handler tok out a = AuthenticationArgs
  { _authJWK         :: JWK
  , _authExpires     :: Maybe UTCTime
  , _authTokCreate   :: UcamWebauthInfo a -> handler tok
  , _authTokUse      :: tok -> handler out
  , _authWAASettings :: SetWAA a
  }

authJWK :: AuthenticationArgs handler tok out a `Lens'` JWK
authJWK f AuthenticationArgs{..} = (\_authJWK -> AuthenticationArgs{_authJWK, ..}) <$> f _authJWK
{-# INLINE authJWK #-}

authExpires :: AuthenticationArgs handler tok out a `Lens'` Maybe UTCTime
authExpires f AuthenticationArgs{..} = (\_authExpires -> AuthenticationArgs{_authExpires, ..}) <$> f _authExpires
{-# INLINE authExpires #-}

authTokCreate :: AuthenticationArgs handler tok out a `Lens'` (UcamWebauthInfo a -> handler tok)
authTokCreate f AuthenticationArgs{..} = (\_authTokCreate -> AuthenticationArgs{_authTokCreate, ..}) <$> f _authTokCreate
{-# INLINE authTokCreate #-}

authTokUse :: AuthenticationArgs handler tok out a `Lens'` (tok -> handler out)
authTokUse f AuthenticationArgs{..} = (\_authTokUse -> AuthenticationArgs{_authTokUse, ..}) <$> f _authTokUse
{-# INLINE authTokUse #-}

authWAASettings :: AuthenticationArgs handler tok out a `Lens'` SetWAA a
authWAASettings f AuthenticationArgs{..} = (\_authWAASettings -> AuthenticationArgs{_authWAASettings, ..}) <$> f _authWAASettings
{-# INLINE authWAASettings #-}

authenticationArgs
    :: forall handler a aas .
      ( Applicative handler
      , aas ~ AuthenticationArgs handler (UcamWebauthInfo a) (UcamWebauthInfo a) a
      )
    => JWK
    -> State aas ()
    -> aas
authenticationArgs _authJWK = (&~) AuthenticationArgs{..}
    where
        _authExpires     = Nothing
        _authTokCreate   = pure
        _authTokUse      = pure
        _authWAASettings = pure ()

--------------------------------------------------
-- * Handler functions
--------------------------------------------------

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
    => AuthenticationArgs handler tok tok a
    -> Maybe (MaybeValidResponse a)
    -> handler (Base64UBSL tok)
ucamWebauthToken aas@AuthenticationArgs{..} mresponse = do
        uwi <- ucamWebauthAuthenticate _authWAASettings mresponse
        tok <- _authTokCreate uwi
        servantMkJWT aas tok

-- | Here, if a request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function and then set the log in token
-- as a cookie. Supply 'pure' to use 'UcamWebauthInfo a' as a token.
ucamWebauthCookie
    :: forall a handler tok out .
       ( ToJSON a
       , ToJWT tok
       , MonadIO handler
       )
    => AuthenticationArgs handler tok out a
    -> Maybe (MaybeValidResponse a)
    -> handler (Cookied out)
ucamWebauthCookie AuthenticationArgs{..} mresponse = do
        uwi <- ucamWebauthAuthenticate _authWAASettings mresponse
        tok <- _authTokCreate uwi
        mApplyCookies <- liftIO $ acceptLogin cookieSettings jwtCfg tok
        out <- _authTokUse tok
        UIO.fromEither . note trans . fmap ($ out) $ mApplyCookies
    where
        trans = err401 { errBody = "Token error" }
        cookieSettings = defaultCookieSettings
        jwtCfg = defaultJWTSettings _authJWK

servantMkJWT
  :: ( ToJWT tok
     , MonadIO handler
     )
  => AuthenticationArgs handler tok tok a
  -> tok -> handler (Base64UBSL tok)
servantMkJWT AuthenticationArgs{..} tok = UIO.fromEitherIO . runExceptT .
  bimapExceptT trans B64UL . ExceptT $ makeJWT tok jwtCfg _authExpires
    where
        trans _ = err401 { errBody = "Token error" }
        jwtCfg = defaultJWTSettings _authJWK
