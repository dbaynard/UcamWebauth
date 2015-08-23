{-|
Module      : Network.Wai.Protocol.Raven.Test
Description : Test Raven authentication
Maintainer  : David Baynard <davidbaynard@gmail.com>

Test Raven authentication using the test server.

__Do Not__ use for real implementations, as the server’s private key is available.

https://raven.cam.ac.uk/project/test-demo/

The functions in this file shadow the names in the "Network.Wai.Protocol.Raven.Auth" module. This is deliberate.

-}
module Network.Wai.Protocol.Raven.Test {-# WARNING "Do not use this module for production code. It is only for testing." #-} (
    module Network.Wai.Protocol.Raven.Test
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
  The Raven Demo settings

  > wlsUrl .= "https://demo.raven.cam.ac.uk/auth/authenticate.html"
-}
ravenSettings :: SetWAA a
ravenSettings = do
        ravenDefSettings
        wSet . validKids .= ["901"]
        wSet . syncTimeOut .= 600
        wSet . wlsUrl .= "https://demo.raven.cam.ac.uk/auth/authenticate.html"
