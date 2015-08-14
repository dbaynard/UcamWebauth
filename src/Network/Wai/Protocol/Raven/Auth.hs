{-|
Module      : Network.Wai.Protocol.Raven.Auth 
Description : Authenticate with Raven
Maintainer  : David Baynard <davidbaynard@gmail.com>

Authenticate with Raven, using the University of Cambridge protocol as implemented
in the "Network.Wai.Protocol.UcamWebauth" module.

<https://raven.cam.ac.uk/project/>

It is possible to test applications using the "Network.Wai.Protocol.Raven.Test" module, instead.

-}
module Network.Wai.Protocol.Raven.Auth (
    module Network.Wai.Protocol.Raven.Auth
  , module X
)   where

-- Prelude
import ClassyPrelude

-- The protocol
import Network.Wai.Protocol.UcamWebauth

import Network.Wai.Protocol.Raven.Internal as X

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven webserver for authentication

  > ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"
-}
ravenAuth :: BlazeBuilder
ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"

ravenSettings :: SetWAA
ravenSettings = do
        ravenDefSettings
        validKids .= ["2"]
