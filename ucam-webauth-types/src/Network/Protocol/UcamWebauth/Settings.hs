{-# LANGUAGE PackageImports #-}

module Network.Protocol.UcamWebauth.Settings
  ( (&~)
  ) where

import "mtl" Control.Monad.State

(&~) :: s -> State s a -> s
(&~) = flip execState
infixl 1 &~
{-# INLINE (&~) #-}
