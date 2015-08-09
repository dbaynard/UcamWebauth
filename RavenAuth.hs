{-|
Module      : RavenAuth
Description : Authenticate with Raven
Maintainer  : David Baynard <davidbaynard@gmail.com>

Authenticate with Raven, using the University of Cambridge protocol

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

ravenAuth :: Z.Builder
ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"

