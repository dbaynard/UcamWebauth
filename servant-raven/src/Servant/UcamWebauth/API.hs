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

module Servant.UcamWebauth.API (
    module Servant.UcamWebauth.API
)   where

import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data

import "servant" Servant.API

-- | Remove the query parameters from a type for easier safe-link making
-- TODO Make injective?
type family Unqueried a = p

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthenticate route a
    = route :> QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[JSON] (UcamWebauthInfo a)

type instance Unqueried (UcamWebAuthenticate route a) = route :> Get '[JSON] (UcamWebauthInfo a)

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthToken route token a
    = route :> QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[OctetStream] token

type instance Unqueried (UcamWebAuthToken route token a) = route :> Get '[OctetStream] token

