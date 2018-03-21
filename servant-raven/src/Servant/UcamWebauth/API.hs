{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeInType #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Servant.UcamWebauth.API (
    module Servant.UcamWebauth.API
)   where

import "ucam-webauth-types" Data.ByteString.B64
import "ucam-webauth-types" UcamWebauth.Data
import "ucam-webauth-types" UcamWebauth.Data.Internal

import "servant" Servant.API

import "cookie" Web.Cookie

-- | Base 64 (URL) encoded 'ByteString's should be serializable as 'OctetStream's.
-- They are already serializable as 'JSON' thanks to the ToJson instance.
instance MimeRender OctetStream (Base64UBSL tag) where
    mimeRender _ = unB64UL

-- TODO Make safe
instance MimeUnrender OctetStream (Base64UBSL tag) where
    mimeUnrender _ = pure . B64UL

-- | Remove the query parameters from a type for easier safe-link making
-- TODO Make injective?
type family Unqueried a = p

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebauthAuthenticate route a
    = UcamWebauthToken '[JSON] route (UcamWebauthInfo a) a

type instance Unqueried (UcamWebauthAuthenticate route a) = route :> Get '[JSON] (UcamWebauthInfo a)

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebauthToken typs route token a
    = route :> QueryParam "WLS-Response" (MaybeValidResponse a) :> Get typs token

type instance Unqueried (UcamWebauthToken typs route token a) = route :> Get typs token

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebauthCookie verb typs route token a
    = route :> QueryParam "WLS-Response" (MaybeValidResponse a) :> verb typs (Cookied token)

type instance Unqueried (UcamWebauthCookie verb typs route token a) = route :> verb typs (Cookied token)

-- | Wrap an output in a pair of cookies (for authentication with XSRF
-- protection)
type Cookied a = Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] a
