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
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data.Internal

import "servant" Servant.API

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
type UcamWebAuthenticate route a
    = UcamWebAuthToken '[JSON] route (UcamWebauthInfo a) a

type instance Unqueried (UcamWebAuthenticate route a) = route :> Get '[JSON] (UcamWebauthInfo a)

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthToken typs route token a
    = UcamWebAuthCookie Get typs route token a

type instance Unqueried (UcamWebAuthToken typs route token a) = route :> Get typs token

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthCookie verb typs route token a
    = route :> QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> verb typs token

type instance Unqueried (UcamWebAuthCookie verb typs route token a) = route :> verb typs token
