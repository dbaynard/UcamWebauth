{-|
Module      : Servant.Raven.Test
Description : Test Raven authentication
Maintainer  : David Baynard <davidbaynard@gmail.com>

Test Raven authentication using the test server.

__Do Not__ use for real implementations, as the server’s private key is available.

https://raven.cam.ac.uk/project/test-demo/

The functions in this file shadow the names in the "Servant.Raven.Auth" module. This is deliberate.

-}
{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , DataKinds
  , FlexibleContexts
  , OverloadedStrings
  , ScopedTypeVariables
  , TemplateHaskell
  , TypeApplications
  , TypeFamilies
  #-}

module Servant.Raven.Test {-# WARNING "Do not use this module for production code. It is only for testing." #-}
  ( ravenSettings
  , module X
  ) where

import "file-embed"         Data.FileEmbed
import "microlens-ghc"      Lens.Micro.GHC
import "microlens-mtl"      Lens.Micro.Mtl
import "this"               Servant.Raven.Internal as X
import "ucam-webauth-types" UcamWebauth.Data

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven Demo settings

  > wlsUrl .= "https://demo.raven.cam.ac.uk/auth/authenticate.html"
-}
ravenSettings
  :: forall baseurl api endpoint a .
    ( UcamWebauthConstraint baseurl api endpoint a
    )
  => SetWAA a
ravenSettings = do
  ravenDefSettings @baseurl @api @endpoint
  wSet . validKids .= ["901"]
  wSet . importedKeys . at "901" .= Just $(embedFile "static/pubkey901.crt")
  wSet . syncTimeOut .= 600
  wSet . wlsUrl .= "https://demo.raven.cam.ac.uk/auth/authenticate.html"
