-- |
-- Module      : Servant.Redirect.API
-- Description : Redirects in an API
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
-- Redirection is a feature of many APIs. For example, the
-- [UcamWebauth](https://raven.cam.ac.uk/project/) protocol (specifically
-- the [WAA->WLS communication
-- protocol](https://raven.cam.ac.uk/project/waa2wls-protocol.txt)) relies
-- on http redirects for user logins.
--
-- This module allows @servant@ APIs to include this information, thereby
-- ensuring the corresponding handlers implement the behaviour.
--
-- Note that this module should not be used for error redirection. Look for
-- various @servant-exceptions@ packages, for an option to include those
-- errors in the API type.

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

module Servant.Redirect.API
  ( -- * Redirects

    -- $redirect

    -- ** Types

    Redirect
  , RedirectLink
  , Redirect'
  , PostRedirect
  , AuthCookieRedirect

    -- ** Handlers

  , redirect

    -- * Rerouting

    -- $reroute

    -- ** Types

  , Linked
  , SelfLinked

    -- ** Handlers

  , reroute
  , reroute'
  ) where

import "base" Control.Monad.IO.Class
import "base" Data.Kind
import "base" Data.Proxy
  (Proxy(..))
import "base" GHC.TypeLits
import "servant" Servant.API

--------------------------------------------------
-- $redirect
--
-- An http redirection sets the @Location@ header. For @servant@, this
-- corresponds to a 'Headers' wrapper around the return type, which should
-- be 'NoContent'. The headers themselves are a type-level 'HList' of
-- 'Servant.API.Header.Header' types.
--
-- The implementation in 'Redirect'' allows the list of headers to be
-- extended; this is not possible for 'Redirect'.

-- | Redirect to location @loc@.
--
-- Supply a 'StdMethod' (e.g. 'GET', 'POST'), the redirect status code,
-- a list of acceptable content types (corresponding to the 'NoContent'
-- value) and the location.
--
-- The handler implementation determines the kind of @loc@ (it will usually
-- be 'Data.Kind.Type').
type Redirect (method :: StdMethod) (code :: Nat) contentTypes (loc :: k)
    = Redirect' method code contentTypes '[] loc

-- | Redirect to a 'Link'
--
-- A 'Link' is correct by construction.
type RedirectLink (method :: StdMethod) (code :: Nat)
    = Redirect method code '[] Link

-- | Redirect to location @loc@.
--
-- Like 'Redirect' but allowing for custom headers.
--
-- TODO Does it need a content-types list? Shouldn't it always be an empty
-- list?
type Redirect' (method :: StdMethod) (code :: Nat) contentTypes headers (loc :: k)
    = Verb method code contentTypes (Headers (Header "Location" loc ': headers) NoContent)

-- | Redirect using JSON and a POST request.
--
-- TODO why use JSON?
type PostRedirect (code :: Nat) (loc :: k)
    = Redirect 'POST code '[JSON] loc

-- | Redirect suitable for setting cookies on authentication.
--
-- TODO why use JSON/PlainText content-type when there's no content?
type AuthCookieRedirect (method :: StdMethod) (loc :: k)
    = Redirect method 302 '[JSON, PlainText] loc

--------------------------------------------------

-- | Redirect to @loc@
--
-- Can be used as @'redirect' \@'Link'@. Corresponds to 'Redirect'.
redirect
  :: forall loc handler withLocation .
    ( ToHttpApiData loc
    , MonadIO handler
    , AddHeader "Location" loc NoContent withLocation
    )
  => loc -- ^ what to put in the @Location@ header
  -> handler withLocation
redirect = pure . flip addHeader NoContent

--------------------------------------------------
-- $reroute
--
-- When working with an API, it should be possible to generate the
-- @Location@ header value from the API itself.
--
-- The 'Linked' and 'SelfLinked' constraints enforce that a link
-- corresponds to a route within an API.

-- | Is @route@ a valid link within @api@?
type Linked route api =
  ( MkLink route Link ~ Link
  , IsElem route api
  , HasLink route
  )

-- | Is @route@ a valid link within @route@?
--
-- @'IsElem' route route@ trivially returns @()@, indicating the constraint
-- is satisfies, so this just checks the link itself is valid.
type SelfLinked route = Linked route route

-- | Redirect to @route@.
--
-- This generates the redirect link from the supplied servant @route@.
-- Note that it /doesn’t/ check that the @route@ is part of any particular
-- API. See 'reroute'' for that.
reroute
  :: forall (route :: Type) handler withLocation .
    ( MonadIO handler
    , AddHeader "Location" Link NoContent withLocation
    , SelfLinked route
    )
  => handler withLocation
reroute = reroute' @route @route

-- | Redirect to @route@, as 'reroute'.
--
-- This generates the redirect link if the supplied servant @route@ is
-- a valid route in the supplied @api@.
reroute'
  :: forall (api :: Type) (route :: Type) handler withLocation .
    ( MonadIO handler
    , Linked route api
    , AddHeader "Location" Link NoContent withLocation
    )
  => handler withLocation
reroute' = redirect @Link $ Proxy @api `safeLink` Proxy @route
