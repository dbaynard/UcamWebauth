{-|
Module      : Servant.UcamWebauth.API
Description : API for UcamWebauth endpoints
Maintainer  : David Baynard <davidbaynard@gmail.com>

Use 'UcamWebauthCookie' or 'UcamWebauthToken' for defaults.

 -}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilyDependencies #-}
{-# LANGUAGE TypeInType #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Servant.UcamWebauth.API
  ( UcamWebauthCookie
  , UcamWebauthToken
  -- * Helpers
  , UcamWebauthEndpoint
  , UcamWebauthAuthenticate
  , WLSResponse
  -- * Wrappers
  , Cookied
  ) where

import "base" Data.Kind

import "ucam-webauth-types" Data.ByteString.B64
import "ucam-webauth-types" UcamWebauth.Data

import "servant" Servant.API
import "servant-auth" Servant.Auth

import "cookie" Web.Cookie

-- | Base 64 (URL) encoded 'ByteString's should be serializable as 'OctetStream's.
-- They are already serializable as 'JSON' thanks to the 'ToJson' instance.
instance MimeRender OctetStream (Base64UBSL tag) where
    mimeRender _ = unB64UL

-- TODO Make safe
-- | Base 64 (URL) encoded 'ByteString's should be serializable as 'OctetStream's.
-- They are already deserializable from 'JSON' thanks to the 'FromJSON' instance.
instance MimeUnrender OctetStream (Base64UBSL tag) where
    mimeUnrender _ = pure . B64UL

-- | Transform a given endpoint to be valid for UcamWebauth.
type family UcamWebauthEndpoint
    (auth     :: Type)
    (endpoint :: Type)
    = (verb :: Type) | verb -> auth
    where
  UcamWebauthEndpoint Cookie (Verb method statusCode contentTypes a) = Verb method statusCode contentTypes (Cookied a)
  UcamWebauthEndpoint JWT    (Verb method statusCode contentTypes a) = Verb method statusCode contentTypes (Base64UBSL a)
infixr 4 `UcamWebauthEndpoint`

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebauthAuthenticate auth param endpoint
    = WLSResponse param :> auth `UcamWebauthEndpoint` endpoint

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS) using JWTs, returning 'token' as
-- JSON.
type UcamWebauthToken param token
    = UcamWebauthAuthenticate JWT param (Get '[JSON] token)

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS) using Cookies, returning
-- nothing.
type UcamWebauthCookie param
    = UcamWebauthAuthenticate Cookie param (Get '[NoContent] ())

-- | The WLS response as a query parameter, with the supplied parameter to
-- send with the request and receive with the response.
type WLSResponse param
    = QueryParam "WLS-Response" (MaybeValidResponse param)

-- | Wrap an output in a pair of cookies (for authentication with XSRF
-- protection)
type Cookied a = Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] a
