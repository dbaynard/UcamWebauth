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

-- Warp server
import Network.Wai.Handler.Warp

warpit :: IO ()
warpit = run 3000 . application =<< getCurrentTime

