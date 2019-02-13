-- |
-- Module      : rio-servant.src.RIO.Servant
-- Description : Use RIO with servant
-- Copyright   : David Baynard 2019
--
-- License     : BSD-3-Clause OR Apache-2.0
-- Maintainer  : David Baynard <UcamWebauth@baynard.me>
-- Stability   : experimental
-- Portability : unknown
--
-- The [servant-server](//hackage.haskell.org/package/servant-server)
-- library provides a way to serve an API.
--
-- @
-- 'serveWithContext' :: 'HasServer' api context => 'Proxy' api -> 'Context' context -> 'Server' api -> 'Application'
-- @
--
-- This function serves a handler of type @'Server' api@, i.e. a @'ServerT'
-- api 'Servant.Handler'@. However, in cases where such handlers are
-- written as values of type @'ServerT' api ('RIO' env)@ this function does
-- not suffice.
--
-- The function 'hoistServerWithContext' allows serving handlers of type
-- @'ServerT' api m@, if the user supplies a natural transformation from
-- handlers in a context @m@ to handlers in a context 'Servant.Handler'.
--
-- However, there’s a gotcha — exceptions.
--
-- 'Servant.Handler' is defined as follows:
--
-- @
-- newtype 'Servant.Handler' a = 'Servant.Handler' ( 'ExceptT' 'ServantErr' 'IO' a )
-- @
--
-- [Michael
-- Snoyman](https://www.fpcomplete.com/blog/2016/11/exceptions-best-practices-haskell)
-- points out some problems wrapping I/O errors in 'ExceptT': that it is
-- unnecessary as 'IO' can throw them itself, misleading as it implies
-- handling the 'ExceptT' catches errors, and makes composition trickier.
-- [Matt
-- Parsons](http://www.parsonsmatt.org/2017/06/21/exceptional_servant_handling.html)
-- has described a straightforward (though as of @servant-0.12@: out of
-- date) guide to just using 'IO'. The changes introduce
-- 'hoistServerWithContext'.
-- Matt’s solution is to throw the 'ServantErr' values as exceptions. These
-- must then, however, be caught as part of the natural transformation in
-- `hoistServerWithContext'.
--
-- There straightforward solution to that would be to change the 'MonadIO'
-- instance for 'Servant.Handler' to catch 'ServantErr' exceptions in
-- 'liftIO'. But as the servant developers intend to remove 'ExceptT' from
-- the design of servant — see
-- [#841](https://github.com/haskell-servant/servant/issues/841) — such
-- a change is not possible; until 'ExceptT' is removed, this looks like
-- the best option.
--
-- This library supplies a function 'serveRIO' which should be used instead
-- of 'serveWithContext'. This correctly handles 'ServantErr' exceptions.
-- The function 'serveRIONoContext' corresponds to 'serve'.
--
-- Meanwhile, some libraries provide handlers in a 'Servant.Handler'
-- context. This library’s 'rioHandler' function lifts those to a @'RIO'
-- env@ context, throwing @'ServantErr'@ errors as exceptions.
--
-- This module exports "Servant", without the dangerous 'serve' and
-- 'serveWithContext' functions, and so it is recommended that this module
-- is imported **instead** of "Servant".

{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE PackageImports      #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

module RIO.Servant
  ( serveRIO
  , serveRIONoContext
  , rioHandler
  , module Servant
  ) where

import           "mtl" Control.Monad.Except
  (ExceptT(ExceptT))
import           "rio" RIO
import           "servant-server" Servant      hiding
  (Handler(..))
import qualified "servant-server" Servant      hiding
  (serve, serveWithContext)
import           "unliftio" UnliftIO.Exception
  (fromEitherIO, fromException, tryJust)

-- | Serve an @api@ (with 'Context' @context@).
--
-- Like 'serveWithContext' but for 'RIO'.
serveRIO
  :: forall api context env . HasServer api context
  => Proxy api
  -> Context context
  -> env
  -> ServerT api (RIO env)
  -> Application
serveRIO api context env = serveWithContext api context .
    hoistServerWithContext api (Proxy @context) handleServantErr
  where

    handleServantErr :: forall a . RIO env a -> Servant.Handler a
    -- This version is not possible as there is no 'MonadUnliftIO' instance
    -- for 'Servant.Handler'. There is no underlying 'MonadUnliftIO'
    -- instance for 'ExceptT ServantErr IO'.
    -- handleServantErr = handleJust (fromException @ServantErr) throwError . runRIO env
    handleServantErr = errHandlingLiftIO . runRIO env

    errHandlingLiftIO :: forall a . IO a -> Servant.Handler a
    errHandlingLiftIO = Servant.Handler . ExceptT . tryJust (fromException @ServantErr)

-- | Serve an @api@ (with 'Context' @context@).
--
-- Like 'serveWithContext' but for 'RIO'.
serveRIONoContext
  :: forall api env . HasServer api '[]
  => Proxy api
  -> env
  -> ServerT api (RIO env)
  -> Application
serveRIONoContext api = serveRIO api EmptyContext

-- | This escape hatch from a 'Servant.Handler' context throws 'ServantErr'
-- errors as exceptions, in a manner that is compatible with 'serveRIO' and
-- 'serveRIONoContext'.
--
-- Use this to run existing 'Servant.Handler' handlers in a @'RIO' env@
-- context.
rioHandler :: forall env a . Servant.Handler a -> RIO env a
rioHandler = fromEitherIO . Servant.runHandler
