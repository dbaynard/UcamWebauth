-- |
-- Module      : Servant.Redirect.Auth
-- Description : Authentication handlers for servant
-- Copyright   : David Baynard 2019
--
-- License     : BSD-3-Clause OR Apache-2.0
-- Maintainer  : David Baynard <ucamwebauth@baynard.me>
-- Stability   : experimental
-- Portability : unknown

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE AllowAmbiguousTypes        #-}
{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs               #-}
{-# LANGUAGE PackageImports             #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeInType                 #-}
{-# LANGUAGE TypeOperators              #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE ViewPatterns               #-}

module Servant.Redirect.Auth
  ( -- * Authentication errors

    -- $auth-errors

    -- * New API

    matching
  , authenticatedUser

    -- * unliftIO

    -- $exceptt-io

    -- ** Check on laws

    -- $unliftio-laws

  , Handler(Handler)
  , runHandler

    -- * Old API

  , WithAuthenticated
  , throwAllProxied
  ) where

import           "exceptions" Control.Monad.Catch                             hiding
  (Handler)
import           "mtl" Control.Monad.Except
import qualified "unliftio-core" Control.Monad.IO.Unlift                      as UIO
import           "base" Data.Kind
import           "base" GHC.Generics
import           "base" GHC.TypeLits
import           "http-types" Network.HTTP.Types
import           "servant-server" Servant                                     hiding
  (Handler(..), runHandler)
import qualified "servant-server" Servant
  (Handler(..), runHandler)
import           "servant-auth-server" Servant.Auth.Server
import           "servant-checked-exceptions-core" Servant.Checked.Exceptions
import qualified "unliftio" UnliftIO.Exception                                as UIO

--------------------------------------------------
-- * Authentication errors

-- $auth-errors
--
-- Need to cover
--
-- [400] Bad request
-- [401] Unauthorized
-- [404] Not found

data UnauthorizedError = UnauthorizedError
  deriving (Eq, Read, Show)

instance ErrStatus UnauthorizedError where
  toErrStatus _ = badRequest400

-- authenticateded
  -- :: forall api handler . handler 

--------------------------------------------------
-- * New api
--
-- TODO First class families!

-- | Does the @api@ explicitly throw any errors, by containing a 'Throws'
-- term?
type family ThrowsAnError api :: Constraint where
  ThrowsAnError (Throws err :> downstream) = ()
  ThrowsAnError (upstream :> downstream)   = ThrowsAnError downstream
  ThrowsAnError (left :<|> right)          = (ThrowsAnError left, ThrowsAnError right)
  ThrowsAnError api                        = TypeError
    ('ShowType api ':<>: 'Text " doesn’t explicitly throw any errors.")

-- | Does the @api@ explicitly throw the specific error @err@, by
-- containing a @'Throws' err@ term?
type family ThrowsError err api :: Constraint where
  ThrowsError err (Throws err :> downstream) = ()
  ThrowsError err (upstream :> downstream)   = ThrowsError err downstream
  ThrowsError err (left :<|> right)          = (ThrowsError err left, ThrowsError err right)
  ThrowsError err api                        = TypeError
    ('ShowType api ':<>: 'Text " doesn’t explicitly throw the error " ':<>: 'ShowType err)

-- | What errors does the API throw, explicitly?
type family ErrorsThrown api :: [Type] where
  ErrorsThrown (Throws err :> downstream) = err ': ErrorsThrown downstream
  ErrorsThrown (upstream :> downstream)   = ErrorsThrown downstream
  ErrorsThrown (left :<|> right)          = Append (ErrorsThrown left) (ErrorsThrown right)
  ErrorsThrown api                        = '[]

-- | Append two lists of types.
type family Append (a :: [k]) (b :: [k]) :: [k] where
  Append '[] b        = b
  Append a '[]        = a
  Append (a0 ': as) b = a0 ': Append as b

-- | If @pattern@ matches @match@, run the handler function, otherwise
-- throw the @matchErr@.
--
-- TODO This looks like the composition of 'Maybe' functions…
matching
  :: forall value handler matchErr errs match pattern result .
    ( IsMember matchErr errs
    , result ~ Envelope errs value
    , Applicative handler
    )
  => (pattern -> Maybe match)  --  ^ Select the matching cases
  -> matchErr                  --  ^ The error on match failure
  -> (match -> handler result) --  ^ Handler for match
  -> pattern                   --  ^ The pattern against which to test
  -> handler result
matching select _ f (select -> Just match) = f match
matching _ matchErr _ _                    = pure $ toErrEnvelope matchErr

authenticatedUser
  :: AuthResult user -> Maybe user
authenticatedUser (Authenticated user) = Just user
authenticatedUser _                    = Nothing

--------------------------------------------------
-- * UnliftIO
--------------------------------------------------

-- $exceptt-io
--
-- [Michael
-- Snoyman](https://www.fpcomplete.com/blog/2016/11/exceptions-best-practices-haskell)
-- points out some problems wrapping I/O errors in 'ExceptT': that it is
-- unnecessary as 'IO' can throw them itself, misleading as it implies
-- handling the 'ExceptT' catches errors, and makes composition trickier.
-- [Matt
-- Parsons](http://www.parsonsmatt.org/2017/06/21/exceptional_servant_handling.html)
-- has described a straightforward (though as of @servant-0.12@: out of
-- date) guide to just using 'IO'.  To use this with existing 'Servant.Handler'
-- code though requires an escape hatch to something that can be @lift@ed
-- and more easily composed.
--
-- The changes to @servant@ since Matt’s article mean that instead of using
-- @enter@ there’s a function 'hoistServer' corresponding to the
-- (relatively undocumented) typeclass method 'hoistServerWithContext'.
-- That doesn't play so nicely with type application, though.

-- | Need to override the 'MonadIO' instance for 'Servant.Handler' values
-- to catch 'ServantErr' exceptions.
newtype Handler a = Handler { runHandler' :: Servant.Handler a }
  deriving
    ( Functor, Applicative, Monad, Generic
    , MonadError ServantErr
    , MonadThrow, MonadCatch, MonadMask
    )

-- | The default implementation of 'MonadIO' for 'Servant.Handler' doesn't
-- catch 'ServantErr' exceptions.
--
-- This version ensures all (and only) such exceptions are converted into
-- 'Left' values.
instance MonadIO Handler where
  liftIO :: IO a -> Handler a
  liftIO = Handler . Servant.Handler . ExceptT . UIO.tryJust (UIO.fromException @ServantErr)

-- | Handles 'IO' exceptions
runHandler :: Handler a -> IO (Either ServantErr a)
runHandler = UIO.handleJust (fromException @ServantErr) (pure . throwError) . Servant.runHandler . runHandler'

-- | This instance throws any 'ServantErr' errors as exceptions. These
-- exceptions must be caught by the runtime, as is such an 'IO'-based
-- philosophy. While it is possible to do this manually, with diligence,
-- and while 'MonadBaseControl' instances for 'Handler' are available, the
-- @unliftio@ variant fits better with the 'IO' philosophy, and so the
-- following instance is required.
--
-- 'UIO.fromEitherIO' throws all servant errors as exceptions.
--
-- With the correct 'MonadIO' instance for 'Handler', the default
-- 'withRunInIO' implementation is correct, too.
instance UIO.MonadUnliftIO Handler where
  askUnliftIO :: Handler (UIO.UnliftIO Handler)
  askUnliftIO = pure $ UIO.UnliftIO $ UIO.fromEitherIO . Servant.runHandler . runHandler'

-- $unliftio-laws
--
-- At its heart, there are two ways to produce values of 'Handler':
--
-- @
-- 'return' :: a -> 'Handler' a
-- 'throwError' :: 'ServantErr' -> 'Handler' a
-- @
--
-- 'return' always produces a 'Handler' containing a value, not throwing an
-- error.
--
-- 1.
--
--     @
--       'unliftIO' u . 'return' = 'return'
--     @
--
--     @'unliftIO' u :: 'Handler' a -> 'IO' a@ must not fail for the case where
--     the 'Handler' input represents a valid value.
--
-- 2.
--
--     @
--       'unliftIO' u (m '>>=' f) = 'unliftIO' u m '>>=' 'unliftIO' u . f
--     @
--
--     Each of the following may fail
--
--     @
--       m :: 'Handler' a
--       f :: a -> 'Handler' b
--     @
--
--     The types for various expressions are
--
--     @
--       m '>>=' f :: 'Handler' b
--       'unliftIO' u (m '>>=' f) :: 'IO' b
--       'unliftIO' u m :: 'IO' a
--       'unliftIO' u . f :: a -> 'IO' b
--       'unliftIO' u m '>>=' 'unliftIO' u . f :: 'IO' b
--     @
--
--     If @m@ and @f@ succeed, this holds.
--
--     If @m@ fails, the LHS fails, as does the RHS (whatever happens to @f@).
--     If @f@ fails, the LHS fails, as does the RHS (whatever happens to @u@).
--
-- 3.
--
--     @
--       'askUnliftIO' '>>=' (\\u -> 'liftIO' ('unliftIO' u m)) = m
--     @
--
--     Some types:
--
--     @
--       m :: 'Handler' a
--       'unliftIO' u m :: 'IO' a
--       'liftIO' ('unliftIO' u m) :: 'Handler' a
--       \\u -> 'liftIO' ('unliftIO' u m) :: 'UnliftIO' 'Handler' -> 'Handler' a
--       'askUnliftIO' :: 'Handler' ('UnliftIO' 'Handler')
--       'askUnliftIO' '>>=' (\\u -> 'liftIO' ('unliftIO' u m)) :: 'Handler' a
--     @
--
--     'askUnliftIO' should always succeed.
--     If @m@ succeeds, then the LHS should succeed.
--     If @m fails, then the LHS should fail (in the bound function).
--
--     This needs a 'liftIO' implementation which catches any exceptions thrown
--     by 'unliftIO'.
--
-- Therefore the laws are met if any value of 'askUnliftIO' produces valid
-- 'IO' actions for valid 'Handler' actions and throws an exception for
-- every error, including 'ServantErr' results.

--------------------------------------------------
-- * Old API

-- | Constraints for authenticated endpoints
type WithAuthenticated (api :: Type) (context :: [Type]) (handler :: Type -> Type) =
  ( HasServer api context
  , ThrowAll (ServerT api Handler)
  , MonadIO handler
  )

-- | Throw an error throughout an api.
throwAllProxied
  :: forall api context m . WithAuthenticated api context m
  => Proxy api
  -> Proxy context
  -> Proxy m
  -> ServantErr
  -> ServerT api m
throwAllProxied api context _ =
  hoistServerWithContext api context (UIO.fromEitherIO @_ @m . runHandler) .
  throwAll @(ServerT api Handler)

