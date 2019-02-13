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
-- This module exports the API of "Servant", without the dangerous 'serve'
-- and 'serveWithContext' functions, and so it is recommended that this
-- module is imported __instead__ of "Servant".
--
-- = Serving handlers
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
-- = Natural transformations
--
-- The function 'hoistServerWithContext' allows serving handlers of type
-- @'ServerT' api m@, if the user supplies a natural transformation from
-- handlers in a context @m@ to handlers in a context 'Servant.Handler'.
--
-- However, there’s a gotcha — exceptions.
--
-- = Exceptions
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
-- = RIO
--
-- This library supplies a function 'serveRIO' which should be used instead
-- of 'serveWithContext'. This correctly handles 'ServantErr' exceptions.
-- The function 'serveRIONoContext' corresponds to 'serve'.
--
-- Meanwhile, some libraries provide handlers in a 'Servant.Handler'
-- context. This library’s 'rioHandler' function lifts those to a @'RIO'
-- env@ context, throwing @'ServantErr'@ errors as exceptions.

{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE PackageImports      #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

module RIO.Servant
  (
    -- * Using servant with rio

    -- $rio-servant

    -- ** Run a wai application from an API ('RIO' context)

    serveRIO
  , serveRIONoContext
  , serveRIO_
  , serveRIONoContext_

    -- ** Run a 'Servant.Handler' in 'RIO'
  , rioHandler

    -- * Re-exports from "Servant"

    -- ** Handler

    -- $handler
  , Servant.Handler

  , -- ** Construct a wai Application from an API
    Servant.toApplication

  , -- ** Handlers for all standard combinators
    Servant.HasServer(..)
  , Servant.Server
  , Servant.EmptyServer
  , Servant.emptyServer

    -- ** Debugging the server layout
  , Servant.layout
  , Servant.layoutWithContext

    -- ** Enter / hoisting server
  , Servant.hoistServer

  -- *** Functions based on <https://hackage.haskell.org/package/mmorph mmorph>
  , Servant.tweakResponse

  -- ** Context
  , Servant.Context(..)
  , Servant.HasContextEntry(getContextEntry)
  -- *** NamedContext
  , Servant.NamedContext(..)
  , Servant.descendIntoNamedContext

  -- ** Basic Authentication
  , Servant.BasicAuthCheck(BasicAuthCheck, unBasicAuthCheck)
  , Servant.BasicAuthResult(..)

  -- ** General Authentication
  -- , AuthHandler(unAuthHandler)
  -- , AuthServerData
  -- , mkAuthHandler

    -- ** Default error type
  , Servant.ServantErr(..)
    -- *** 3XX
  , Servant.err300
  , Servant.err301
  , Servant.err302
  , Servant.err303
  , Servant.err304
  , Servant.err305
  , Servant.err307
    -- *** 4XX
  , Servant.err400
  , Servant.err401
  , Servant.err402
  , Servant.err403
  , Servant.err404
  , Servant.err405
  , Servant.err406
  , Servant.err407
  , Servant.err409
  , Servant.err410
  , Servant.err411
  , Servant.err412
  , Servant.err413
  , Servant.err414
  , Servant.err415
  , Servant.err416
  , Servant.err417
  , Servant.err418
  , Servant.err422
   -- *** 5XX
  , Servant.err500
  , Servant.err501
  , Servant.err502
  , Servant.err503
  , Servant.err504
  , Servant.err505

  -- ** Re-exports
  , Servant.Application
  , Servant.Tagged (..)
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

-- $rio-servant
--
-- To create handlers in a @'RIO' env@ context, return the value required
-- for success as with 'Servant.Handler'.

-- | Serve an @api@ (with 'Context' @context@).
--
-- Like 'serveWithContext' but for 'RIO'.
serveRIO
  :: forall api context env . HasServer api context
  => Context context
  -> env
  -> ServerT api (RIO env)
  -> Application
serveRIO context env = serveWithContext (Proxy @api) context .
    hoistServerWithContext (Proxy @api) (Proxy @context) handleServantErr
  where

    handleServantErr :: forall a . RIO env a -> Servant.Handler a
    -- This version is not possible as there is no 'MonadUnliftIO' instance
    -- for 'Servant.Handler'. There is no underlying 'MonadUnliftIO'
    -- instance for 'ExceptT ServantErr IO'.
    -- handleServantErr = handleJust (fromException @ServantErr) throwError . runRIO env
    handleServantErr = errHandlingLiftIO . runRIO env

    errHandlingLiftIO :: forall a . IO a -> Servant.Handler a
    errHandlingLiftIO = Servant.Handler . ExceptT . tryJust (fromException @ServantErr)

-- | Serve an @api@ (with no 'Context').
--
-- Like 'serve' but for 'RIO'.
serveRIONoContext
  :: forall api env . HasServer api '[]
  => env
  -> ServerT api (RIO env)
  -> Application
serveRIONoContext = serveRIO @api EmptyContext

-- | Serve an @api@ (with 'Context' @context@).
--
-- Like 'serveRIO' but with explicit 'Proxy'.
serveRIO_
  :: forall api context env . HasServer api context
  => Proxy api
  -> Context context
  -> env
  -> ServerT api (RIO env)
  -> Application
serveRIO_ _ = serveRIO @api

-- | Serve an @api@ (with no 'Context').
--
-- Like 'serveRIONoContext' but with explicit 'Proxy'.
serveRIONoContext_
  :: forall api env . HasServer api '[]
  => Proxy api
  -> env
  -> ServerT api (RIO env)
  -> Application
serveRIONoContext_ _ = serveRIONoContext @api

-- | This escape hatch from a 'Servant.Handler' context throws 'ServantErr'
-- errors as exceptions, in a manner that is compatible with 'serveRIO' and
-- 'serveRIONoContext'.
--
-- Use this to run existing 'Servant.Handler' handlers in a @'RIO' env@
-- context.
rioHandler :: forall env a . Servant.Handler a -> RIO env a
rioHandler = fromEitherIO . Servant.runHandler

-- $handler
--
-- For 'Servant.Handler', only the type is re-exported. There is no need to
-- use either the constructor or destructor.
--
-- Create handlers in a @'RIO' env@ context instead.
--
-- Consume handlers in a 'Servant.Handler' context with 'rioHandler'.
