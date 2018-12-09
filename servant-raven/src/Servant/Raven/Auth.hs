{-|
Module      : Servant.Raven.Auth 
Description : Authenticate with Raven
Maintainer  : David Baynard <ucamwebauth@baynard.me>

Authenticate with Raven, using the University of Cambridge protocol as implemented
in the "Servant.UcamWebauth" module.

<https://raven.cam.ac.uk/project/>

It is possible to test applications using the "Servant.Raven.Test" module, instead.

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

module Servant.Raven.Auth
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
