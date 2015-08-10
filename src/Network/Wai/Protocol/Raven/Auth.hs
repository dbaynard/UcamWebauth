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

import Network.Wai.Protocol.Raven.Internal as X

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven webserver for authentication

  > ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"
-}
ravenAuth :: BBuilder
ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"

