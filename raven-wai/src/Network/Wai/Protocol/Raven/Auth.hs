{-|
Module      : Network.Wai.Protocol.Raven.Auth 
Description : Authenticate with Raven
Maintainer  : David Baynard <davidbaynard@gmail.com>

Authenticate with Raven, using the University of Cambridge protocol as implemented
in the "Network.Wai.Protocol.UcamWebauth" module.

<https://raven.cam.ac.uk/project/>

It is possible to test applications using the "Network.Wai.Protocol.Raven.Test" module, instead.

-}

{-# LANGUAGE
    PackageImports
  , OverloadedStrings
  #-}

module Network.Wai.Protocol.Raven.Auth
  ( ravenSettings
  , ravenDefSettings
  ) where

import "microlens-mtl"      Lens.Micro.Mtl
import "this"               Network.Wai.Protocol.Raven.Internal
import "ucam-webauth-types" UcamWebauth.Data

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven settings

  > wlsUrl .= "https://raven.cam.ac.uk/auth/authenticate.html"
-}
ravenSettings :: SetWAA a
ravenSettings = do
  ravenDefSettings
  wSet . validKids .= ["2"]
  wSet . wlsUrl .= "https://raven.cam.ac.uk/auth/authenticate.html"
