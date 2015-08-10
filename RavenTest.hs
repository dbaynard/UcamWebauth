{-|
Module      : RavenTest
Description : Test Raven authentication
Maintainer  : David Baynard <davidbaynard@gmail.com>

Test Raven authentication using the test server.

__Do Not__ use for real implementations, as the server’s private key is available.

https://raven.cam.ac.uk/project/test-demo/

The functions in this file shadow the names in the "RavenAuth" module. This is deliberate.

-}

module RavenTest {-# WARNING "Do not use this module for production code. It is only for testing." #-} (
    module RavenTest
)   where

-- Prelude
import ClassyPrelude

-- The protocol
import UcamWebauth

-- String handling
import qualified Blaze.ByteString.Builder as Z (Builder)

------------------------------------------------------------------------------
-- * Raven servers

{-|
  The Raven webserver to test authentication

  > ravenAuth = "https://demo.raven.cam.ac.uk/auth/authenticate.html"
-}
ravenAuth :: Z.Builder
ravenAuth = "https://demo.raven.cam.ac.uk/auth/authenticate.html"


