{-|
Module      : Servant.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Servant.Raven.Internal (
    module Servant.Raven.Internal
)   where

-- The protocol
import Servant.UcamWebauth

{-|
  'WAASettings' for Raven
-}
ravenDefSettings :: SetWAA a
ravenDefSettings = pure ()

