{-|
Module      : Servant.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , DataKinds
  , FlexibleContexts
  , RecordWildCards
  , ScopedTypeVariables
  , TypeApplications
  , TypeFamilies
  #-}

module Servant.Raven.Internal
  ( ravenDefSettings
  , Reifies
  , Symbol
  , URI
  -- Rexported
  , UcamWebauthConstraint
  ) where

import "reflection"         Data.Reflection
import "base"               GHC.TypeLits
import "this"               Servant.UcamWebauth.Settings
import "this"               URI.Convert
import "ucam-webauth-types" UcamWebauth.Data

{-|
  'WAASettings' for Raven
-}
ravenDefSettings
  :: forall baseurl api endpoint a .
    ( UcamWebauthConstraint baseurl api endpoint a
    )
  => SetWAA a
ravenDefSettings = ucamWebauthSettings @baseurl @api @endpoint
