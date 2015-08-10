{-|
Module      : Network.Wai.Protocol.Raven.Internal
Description : UcamWebauth to access Raven (test and live)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Wai.Protocol.Raven.Internal (
    module Network.Wai.Protocol.Raven.Internal
  , module X
)   where


-- Prelude
import ClassyPrelude as X

-- The protocol
import Network.Wai.Protocol.UcamWebauth  as X

-- String handling
import qualified Blaze.ByteString.Builder as Z (Builder)

type BBuilder = Z.Builder
