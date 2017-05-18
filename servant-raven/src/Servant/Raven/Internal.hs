{-|
Module      : Servant.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}

module Servant.Raven.Internal (
    module Servant.Raven.Internal
  , Reifies
  , URIAuth(..)
  , Symbol
)   where

import "base" GHC.TypeLits

import "reflection" Data.Reflection
import "network-uri" Network.URI

import "servant" Servant.Utils.Links

-- The protocol
import Servant.UcamWebauth

{-|
  'WAASettings' for Raven
-}
ravenDefSettings
    :: forall baseurl api e (route :: Symbol) token a endpoint .
       ( Reifies baseurl URIAuth
       , IsElem endpoint api
       , HasLink endpoint
       , endpoint ~ Unqueried e
       , e ~ UcamWebAuthToken route token a
       )
    => SetWAA a
ravenDefSettings = ucamWebAuthSettings @baseurl @api @e

