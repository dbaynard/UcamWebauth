{-|
Module      : Servant.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DeriveLift #-}

module Servant.Raven.Internal
  ( uri
  , ravenDefSettings
  , Reifies
  , Symbol
  ) where

import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data

import "base" GHC.TypeLits

import "template-haskell" Language.Haskell.TH.Quote
import "template-haskell" Language.Haskell.TH.Syntax
import "errors" Control.Error

import "reflection" Data.Reflection

import "servant" Servant.Utils.Links

import "network-uri" Network.URI

-- The protocol
import "servant-raven" Servant.UcamWebauth.API
import Servant.UcamWebauth

{-|
  'WAASettings' for Raven
-}
ravenDefSettings
    :: forall baseurl api e (route :: Symbol) token a endpoint .
       ( Reifies baseurl URI
       , IsElem endpoint api
       , HasLink endpoint
       , endpoint ~ Unqueried e
       , e ~ UcamWebAuthToken route token a
       )
    => SetWAA a
ravenDefSettings = ucamWebAuthSettings @baseurl @api @e

uri :: QuasiQuoter
uri = QuasiQuoter
    { quoteExp   = \r -> let x = parseURI r ?: error "Not a valid URI" in x `seq` [| x |]
    , quotePat   = const $ error "No quotePat defined for any Network.URI QQ"
    , quoteType  = const $ error "No quoteType defined for any Network.URI QQ"
    , quoteDec   = const $ error "No quoteDec defined for any Network.URI QQ"
    }

deriving instance Lift URIAuth
deriving instance Lift URI
