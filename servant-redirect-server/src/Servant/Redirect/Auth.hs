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

  --, WithAuthenticated
  --, throwAllProxied
  ) where

import           "base" Data.Kind
import           "base" GHC.TypeLits
import           "http-types" Network.HTTP.Types
import           "servant-server" Servant                                     hiding
  (Handler(..), runHandler)
import           "servant-auth-server" Servant.Auth.Server
import           "servant-checked-exceptions-core" Servant.Checked.Exceptions

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
-- * Old API

-- -- | Constraints for authenticated endpoints
-- type WithAuthenticated (api :: Type) (context :: [Type]) (handler :: Type -> Type) =
--   ( HasServer api context
--   , ThrowAll (ServerT api Handler)
--   , MonadIO handler
--   )
-- 
-- -- | Throw an error throughout an api.
-- throwAllProxied
--   :: forall api context m . WithAuthenticated api context m
--   => Proxy api
--   -> Proxy context
--   -> Proxy m
--   -> ServantErr
--   -> ServerT api m
-- throwAllProxied api context _ =
--   hoistServerWithContext api context (UIO.fromEitherIO @_ @m . runHandler) .
--   throwAll @(ServerT api Handler)

