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
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Servant.Raven.Auth
  ( ravenSettings
  , module X
  ) where

import "microlens-mtl" Lens.Micro.Mtl
import "microlens-ghc" Lens.Micro.GHC
import "file-embed" Data.FileEmbed

-- The protocol
import "ucam-webauth-types" UcamWebauth.Data

import "this" Servant.Raven.Internal as X

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven settings

  > wlsUrl .= "https://raven.cam.ac.uk/auth/authenticate.html"
-}
ravenSettings
    :: forall baseurl api endpoint a .
      ( UcamWebauthConstraint baseurl api endpoint a
      )
    => SetWAA a
ravenSettings = do
        ravenDefSettings @baseurl @api @endpoint
        wSet . validKids .= ["2"]
        wSet . importedKeys . at "2" .= Just $(embedFile "static/pubkey2.crt")
        wSet . wlsUrl .= "https://raven.cam.ac.uk/auth/authenticate.html"
