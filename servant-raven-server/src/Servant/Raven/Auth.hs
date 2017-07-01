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

module Servant.Raven.Auth
  ( ravenSettings
  , module X
  ) where


import "microlens-mtl" Lens.Micro.Mtl
import "servant" Servant.Utils.Links hiding (URI)

-- The protocol
import Servant.UcamWebauth.API
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data

import Servant.Raven.Internal as X

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven settings

  > wlsUrl .= "https://raven.cam.ac.uk/auth/authenticate.html"
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
        wSet . validKids .= ["2"]
        wSet . wlsUrl .= "https://raven.cam.ac.uk/auth/authenticate.html"
