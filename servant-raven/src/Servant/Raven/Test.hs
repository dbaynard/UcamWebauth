{-|
Module      : Servant.Raven.Test
Description : Test Raven authentication
Maintainer  : David Baynard <davidbaynard@gmail.com>

Test Raven authentication using the test server.

__Do Not__ use for real implementations, as the server’s private key is available.

https://raven.cam.ac.uk/project/test-demo/

The functions in this file shadow the names in the "Servant.Raven.Auth" module. This is deliberate.

-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Servant.Raven.Test {-# WARNING "Do not use this module for production code. It is only for testing." #-}
  ( ravenSettings
  , module X
  ) where

-- Prelude
import "microlens-mtl" Lens.Micro.Mtl
import "microlens-ghc" Lens.Micro.GHC
import "servant" Servant.Utils.Links hiding (URI)
import "file-embed" Data.FileEmbed

-- The protocol
import "this" Servant.UcamWebauth.API
import "ucam-webauth-types" UcamWebauth.Data

import "this" Servant.Raven.Internal as X

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven Demo settings

  > wlsUrl .= "https://demo.raven.cam.ac.uk/auth/authenticate.html"
-}
ravenSettings
    :: forall baseurl api e a endpoint .
       ( Reifies baseurl URI
       , IsElem endpoint api
       , HasLink endpoint
       , MkLink endpoint ~ Link
       , endpoint ~ Unqueried e
       )
    => SetWAA a
ravenSettings = do
        ravenDefSettings @baseurl @api @e
        wSet . validKids .= ["901"]
        wSet . importedKeys . at "901" .= Just $(embedFile "static/pubkey901.crt")
        wSet . syncTimeOut .= 600
        wSet . wlsUrl .= "https://demo.raven.cam.ac.uk/auth/authenticate.html"
