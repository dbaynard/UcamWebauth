{-|
Module      : Servant.Raven.Auth 
Description : Authenticate with Raven
Maintainer  : David Baynard <davidbaynard@gmail.com>

Authenticate with Raven, using the University of Cambridge protocol as implemented
in the "Servant.UcamWebauth" module.

<https://raven.cam.ac.uk/project/>

It is possible to test applications using the "Servant.Raven.Test" module, instead.

-}

{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}

module Servant.Raven.Auth (
    module Servant.Raven.Auth
  , module X
)   where

import "microlens-mtl" Lens.Micro.Mtl

-- The protocol
import Servant.UcamWebauth

import Servant.Raven.Internal as X

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
