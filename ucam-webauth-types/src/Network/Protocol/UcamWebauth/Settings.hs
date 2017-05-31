{-# LANGUAGE PackageImports #-}

module Network.Protocol.UcamWebauth.Settings (
    module Network.Protocol.UcamWebauth.Settings
)   where

import Network.Protocol.UcamWebauth.Data

import "mtl" Control.Monad.State

{-|
  Type synonym for WAASettings settings type.
-}
type SetWAA a = State (WAAState a) ()

(&~) :: s -> State s a -> s
(&~) = flip execState
infixl 1 &~
{-# INLINE (&~) #-}
