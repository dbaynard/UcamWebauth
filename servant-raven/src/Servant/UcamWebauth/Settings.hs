{-|
Module      : Servant.UcamWebauth.Settings
Description : Authenticate using the Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

This module generates the settings for the University of Cambridge’s Ucam-Webauth protocol.
 -}

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

module Servant.UcamWebauth.Settings
  ( ucamWebAuthSettings
  , authURI
  ) where

import "this" Servant.UcamWebauth.API

import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data

import "base" Data.Kind
import "base" Data.Proxy

import "text" Data.Text (Text)
import "text" Data.Text.Encoding
import qualified "bytestring" Data.ByteString.Char8 as B8

import "servant" Servant.Utils.Links
import qualified "uri-bytestring" URI.ByteString as UB
import URI.Convert hiding (URI)

import "errors" Control.Error
import "reflection" Data.Reflection
import "microlens-mtl" Lens.Micro.Mtl
import "microlens" Lens.Micro

{-
 -import "aeson" Data.Aeson.Types hiding ((.=))
 -}


-- | The default settings for UcamWebauth should generate the application
-- link from the api type.
--
-- This must be reified with a 'Network.URI.URIAuth' value corresponding to
-- the base url of the api.
ucamWebAuthSettings
    :: forall baseurl (api :: Type) (e :: Type) a endpoint .
       ( IsElem endpoint api
       , HasLink endpoint
       , MkLink endpoint ~ Link
       , endpoint ~ Unqueried e
       , Reifies baseurl UB.URI
       )
    => SetWAA a
ucamWebAuthSettings = do
        wSet . applicationUrl .= authLink
    where
        authLink :: Text
        authLink = authURI baseUri . linkURI $ safeLink (Proxy @api) (Proxy @endpoint)

        baseUri :: UB.URI
        baseUri = reflect @baseurl Proxy

-- TODO kinda fragile
authURI :: UB.URI -> URI -> Text
authURI = curry $ fromMaybe "" . fmap (decodeUtf8 . UB.serializeURIRef') . authURI'

-- TODO super fragile
authURI' :: (UB.URI, URI) -> Maybe UB.URI
authURI' (baseUri, uri) = do
    relUri <- uriByteStringRel uri
    let rel = relUri &~ do
            UB.authorityL .= (baseUri ^. UB.authorityL)
            UB.pathL %= B8.cons '/'
    pure $ UB.uriScheme baseUri `UB.toAbsolute` rel


