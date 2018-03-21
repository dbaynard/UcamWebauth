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

import "ucam-webauth-types" UcamWebauth.Data

import "base" GHC.TypeLits

import "reflection" Data.Reflection

import "servant" Servant.Utils.Links hiding (URI)
import "this" URI.Convert

-- The protocol
import "this" Servant.UcamWebauth.API
import "this" Servant.UcamWebauth.Settings

{-|
  'WAASettings' for Raven
-}
ravenDefSettings
    :: forall baseurl api e a endpoint .
       ( Reifies baseurl URI
       , IsElem endpoint api
       , HasLink endpoint
       , MkLink endpoint ~ Link
       , endpoint ~ Unqueried e
       )
    => SetWAA a
ravenDefSettings = ucamWebauthSettings @baseurl @api @e

