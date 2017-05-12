{-|
Module      : Network.Wai.Protocol.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Wai.Protocol.Raven.Internal (
    module Network.Wai.Protocol.Raven.Internal
)   where

-- Prelude
import ClassyPrelude

-- The protocol
import Network.Wai.Protocol.UcamWebauth

{-|
  'WAASettings' for Raven
-}
ravenDefSettings :: SetWAA a
ravenDefSettings = def

