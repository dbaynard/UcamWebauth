{-# OPTIONS_HADDOCK hide, not_here #-}
{-# LANGUAGE
    PackageImports
  #-}

{-|
Module      : UcamWebauth.Internal
Description : Ucam-Webauth protocol internals
Maintainer  : David Baynard <ucamwebauth@baynard.me>

-}

module UcamWebauth.Internal
  ( module UcamWebauth.Internal
  ) where

import "base" Control.Applicative (empty, Alternative)

{-|
  Lift a 'Maybe' value.
-}
liftMaybe :: Alternative f => Maybe a -> f a
liftMaybe = maybe empty pure
