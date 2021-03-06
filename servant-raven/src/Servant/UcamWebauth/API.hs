{-|
Module      : Servant.UcamWebauth.API
Description : API for UcamWebauth endpoints
Maintainer  : David Baynard <ucamwebauth@baynard.me>

Use 'UcamWebauthCookie' or 'UcamWebauthToken' for defaults.

 -}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , DataKinds
  , FlexibleContexts
  , MultiParamTypeClasses
  , NamedFieldPuns
  , RecordWildCards
  , ScopedTypeVariables
  , TypeApplications
  , TypeFamilyDependencies
  , TypeInType
  , TypeOperators
  #-}

module Servant.UcamWebauth.API
  ( UcamWebauthCookie
  , UcamWebauthCookieRedir
  , UcamWebauthToken
  -- * Helpers
  , UcamWebauthEndpoint
  , UcamWebauthAuthenticate
  , WLSResponse
  -- * Wrappers
  , Cookied
  ) where

import "ucam-webauth-types" Data.ByteString.B64
import "base"               Data.Kind
import "this"               Extra.Servant.Redirect.API
import "servant"            Servant.API
import "servant-auth"       Servant.Auth
import "ucam-webauth-types" UcamWebauth.Data
import "cookie"             Web.Cookie

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
    :: Type
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
    = UcamWebauthAuthenticate Cookie param (Get '[PlainText] NoContent)

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS) using Cookies, returning
-- nothing, with a 302 redirect.
type UcamWebauthCookieRedir param (loc :: k)
    = UcamWebauthAuthenticate Cookie param (AuthCookieRedirect 'GET loc)

-- | The WLS response as a query parameter, with the supplied parameter to
-- send with the request and receive with the response.
type WLSResponse param
    = QueryParam "WLS-Response" (MaybeValidResponse param)

-- | Wrap an output in a pair of cookies (for authentication with XSRF
-- protection)
--
-- This is like 'AddHeader' but can be used without impredicative polymorphism.
type family Cookied a where
  Cookied (Headers headers a) = Headers  (Header "Set-Cookie" SetCookie ': Header "Set-Cookie" SetCookie ': headers) a
  Cookied                  a  = Headers '[Header "Set-Cookie" SetCookie  , Header "Set-Cookie" SetCookie]            a
