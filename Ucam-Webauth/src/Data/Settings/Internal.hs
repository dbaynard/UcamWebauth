{-# OPTIONS_HADDOCK hide, not_here #-}
{-# LANGUAGE PackageImports #-}

{-|
Module      : Data.Settings.Internal
Description : Settings types using MonadState
Maintainer  : David Baynard <davidbaynard@gmail.com>

See <https://ocharles.org.uk/blog/posts/2015-07-23-another-approach-to-default-variables.html>
for an explanation of this approach.

-}

module Data.Settings.Internal (
    module Data.Settings.Internal
  , get
)   where

import "mtl" Control.Monad.State.Strict

------------------------------------------------------------------------------
-- * Default Settings
{- $settings
  See <https://ocharles.org.uk/blog/posts/2015-07-23-another-approach-to-default-variables.html>
  for an explanation of this approach.

  There is no need for users of the module to import "Control.Monad.State.Strict", as this section
  exports all the necessary machinery.
-}

type Mod a = State a ()

{-|
  'def' means ‘use default settings’.

  > def :: forall a . State a ()
  > def = return ()
-}
def :: Mod a
def = return ()

{-|
  'config' modifies the default configuration for settings provided, with the 'State' function provided
-}
config :: a -> Mod a -> a
config = flip execState
