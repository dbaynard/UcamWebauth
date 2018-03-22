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
  -- Rexported
  , UcamWebauthConstraint
  ) where

import "ucam-webauth-types" UcamWebauth.Data

import "base" GHC.TypeLits

import "reflection" Data.Reflection

import "this" URI.Convert

-- The protocol
import "this" Servant.UcamWebauth.Settings

{-|
  'WAASettings' for Raven
-}
ravenDefSettings
    :: forall baseurl api endpoint a .
      ( UcamWebauthConstraint baseurl api endpoint a
      )
    => SetWAA a
ravenDefSettings = ucamWebauthSettings @baseurl @api @endpoint

