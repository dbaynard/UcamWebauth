{-# OPTIONS_HADDOCK hide, not_here #-}

{-|
Module      : Network.Protocol.UcamWebauth.Internal
Description : Ucam-Webauth protocol internals
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Internal (
    module Network.Protocol.UcamWebauth.Internal
)   where

import ClassyPrelude
import Control.Applicative (empty, Alternative)

{-|
  Lift a 'Maybe' value.
-}
liftMaybe :: Alternative f => Maybe a -> f a
liftMaybe = maybe empty pure
