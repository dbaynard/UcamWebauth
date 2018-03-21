{-|
Module      : Network.Wai.Protocol.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

{-# LANGUAGE PackageImports #-}

module Network.Wai.Protocol.Raven.Internal
  ( ravenDefSettings
  ) where

-- The protocol
import "ucam-webauth-types" UcamWebauth.Data

{-|
  'WAASettings' for Raven
-}
ravenDefSettings :: SetWAA a
ravenDefSettings = pure ()

