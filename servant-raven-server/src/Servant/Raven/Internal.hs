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
{-# LANGUAGE RecordWildCards #-}

module Servant.Raven.Internal
  ( ravenDefSettings
  , Reifies
  , Symbol
  , URI
  ) where

import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data

import "base" GHC.TypeLits

import "reflection" Data.Reflection

import "servant" Servant.Utils.Links hiding (URI)
import URI.Convert

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

