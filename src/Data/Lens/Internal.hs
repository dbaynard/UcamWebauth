{-# OPTIONS_HADDOCK hide, not_home #-}

{-|
Module      : Data.Lens.Internal
Description : Lightweight locally defined lens types and combinators
Maintainer  : David Baynard <davidbaynard@gmail.com>

Why bother importing the lens library for such a trivial task?

-}

module Data.Lens.Internal (
    module Data.Lens.Internal
)   where

import ClassyPrelude
import Control.Applicative (Const(..))
import Control.Monad.State.Strict

------------------------------------------------------------------------------
-- * Lenses
{- $lenses
  Rather than import a lens library, the simple functions required can be easily
  implemented here.

  TODO The types should be compatible with other lens libraries.
-}

{-|
  A 'Lens' takes a function to modify a value of type 'a' in a record of type 's'
  to give a value of type 'b' under the context 'f', in a record of type 't' under
  the context 'f', for any valid 'Functor' context 'f'.
-}
type Lens s t a b = forall f . (Functor f) => (a -> f b) -> s -> f t

{-|
  A 'Lens'' takes a function to modify a value of type 'a' in a record of type 's'
  to give a value of type 'a' under the context 'f', in a record of type 's' under
  the context 'f', for any valid 'Functor' context 'f'.
-}
type Lens' s a = Lens s s a a

{-|
  Also known as 'over', '%~' uses the supplied function to replace values within data types

  > l %~ f = runIdentity . l (Identity . f)

  For 'Lens'' the type simplifies to

  > (%~) :: Lens' s a -> (a -> a) -> s -> s

  'over' has not been implemented.
-}
(%~) :: Lens s t a b -> (a -> b) -> s -> t
l %~ f = runIdentity . l (Identity . f)
infixr 4 %~

{-|
  Also known as 'assign', '.=' assigns the state in a 'StateT' environment to that supplied

  > l .= v = modify $ l %~ const v
  nad-ST

  For 'Lens'' the type simplifies to

  > (.=) :: MonadState s m => Lens' s a -> a -> m ()

  '.=' conflicts with 'Data.Aeson..=' from "Data.Aeson"

  'assign' has not been implemented.
-}
(.=) :: MonadState s m => Lens s s a b -> b -> m ()
l .= v = modify $ l %~ const v
infix 4 .=

{-|
  Also know (flipped) as 'view', '^.' extracts the value from a record 's' of type 'a' by
  the given 'Lens'.

  'view' is more useful in function composition.
-}
(^.) :: s -> Lens s t a b -> a
s ^. l = getConst . l Const $ s
infixl 8 ^.

view :: Lens s t a b -> s -> a
{-# INLINE view #-}
view l s = s ^. l
