-- |
-- Module      : Servant.Redirect
-- Description : Redirect handlers
-- Copyright   : David Baynard 2019
--
-- License     : BSD-3-Clause OR Apache-2.0
-- Maintainer  : David Baynard <ucamwebauth@baynard.me>
-- Stability   : experimental
-- Portability : unknown
--
-- Based on [Alp Mestanogullari’s approach to (success)
-- redirects](https://gist.github.com/alpmestan/757094ecf9401f85c5ba367ca20b8900)
--
-- See "Servant.Redirect.API".

{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ConstraintKinds     #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE PackageImports      #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeInType          #-}
{-# LANGUAGE TypeOperators       #-}

module Servant.Redirect
  ( -- $redirect
    -- * Specializations
    rerouteCookie
    -- * Reexport
  , module X
  ) where

import "base" Control.Monad.IO.Class
import "base" Data.Kind
import "servant-server" Servant
import "servant-redirect" Servant.Redirect.API as X

-- $redirect
--
-- Redirect according to the ServerT type.
--
-- Typically, this type will be a specialization of
--
-- > type 'Redirect' (method :: 'StdMethod') (code :: 'Nat') contentTypes (loc :: k)
-- >     = 'Verb' method code contentTypes ('Headers' '['Header' "Location" loc] 'NoContent')
--
-- See "Servant.Redirect.API" from @servant-raven@.

--------------------------------------------------
-- * Specializations
--------------------------------------------------

-- | A specialization of 'reroute'
rerouteCookie
  :: forall (route :: Type) (method :: StdMethod) handler .
    ( MonadIO handler
    , SelfLinked route
    )
  => ServerT (AuthCookieRedirect method Link) handler
rerouteCookie = reroute @route
