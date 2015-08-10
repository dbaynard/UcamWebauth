{-|
Module      : RavenAuth
Description : Authenticate with Raven
Maintainer  : David Baynard <davidbaynard@gmail.com>

Authenticate with Raven, using the University of Cambridge protocol as implemented
in the "UcamWebauth" module.

<https://raven.cam.ac.uk/project/>

It is possible to test applications using the "RavenTest" module, instead.

-}

module RavenAuth (
    module RavenAuth
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
  The Raven webserver for authentication

  > ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"
-}
ravenAuth :: Z.Builder
ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"

