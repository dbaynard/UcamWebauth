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

import "ucam-webauth" Network.Protocol.UcamWebauth

import "base" Data.Kind
import "base" Data.Proxy
import "base" GHC.TypeLits
import "reflection" Data.Reflection

import "microlens-mtl" Lens.Micro.Mtl

import "text" Data.Text (Text)
import qualified "text" Data.Text as T

import "servant" Servant.API
import "servant" Servant.Utils.Links

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

