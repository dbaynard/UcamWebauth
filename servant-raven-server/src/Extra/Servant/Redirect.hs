{-|
Module      : Extra.Servant.Redirect
Description : Handlers for redirection
Maintainer  : David Baynard <davidbaynard@gmail.com>

Based on Alp Mestanogullari’s approach to (success) redirects, from
<https://gist.github.com/alpmestan/757094ecf9401f85c5ba367ca20b8900>

The 'reroute' family of functions rely on redirection to type safe links, as managed by "servant".

 -}

{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , ConstraintKinds
  , DataKinds
  , FlexibleContexts
  , ScopedTypeVariables
  , TypeApplications
  , TypeFamilies
  , TypeInType
  , TypeOperators
  #-}

module Extra.Servant.Redirect
  ( -- $redirect
    Rerouteable
  , Rerouteable'
  , reroute
  , reroute'
  , redirect
  -- * Specializations
  , rerouteCookie
  -- * Reexport
  , module X
  ) where

import "base"           Control.Monad.IO.Class
import "base"           Data.Kind
import "servant-raven"  Extra.Servant.Redirect.API as X
import "servant-server" Servant

-- $redirect
-- 
-- Redirect according to the ServerT type.
-- 
-- Typically, this type will be a specialization of
--
-- > type Redirect (method :: StdMethod) (code :: Nat) contentTypes (loc :: k)
-- >     = Verb method code contentTypes (Headers '[Header "Location" loc] NoContent)
--
-- See "servant-raven" 'Extra.Servant.Redirect.API'

-- | Redirect to 'loc'
redirect
  :: forall handler loc withLocation .
    ( ToHttpApiData loc
    , MonadIO handler
    , AddHeader "Location" loc NoContent withLocation
    )
  => loc -- ^ what to put in the 'Location' header
  -> handler withLocation
redirect = pure . flip addHeader NoContent

-- | Is 'route' a valid link within 'api'
type Rerouteable' route api =
  ( MkLink route ~ Link
  , IsElem route api
  , HasLink route
  )

-- | Is 'route' a valid link within 'route
type Rerouteable route = Rerouteable' route route

-- | Redirect to 'route'
--
-- This generates the redirect link from the supplied servant 'route'.
-- Note that it /doesn’t/ check that the 'route' is part of any particular
-- api. See 'reroute\'' for that.
reroute
  :: forall (route :: Type) handler withLocation .
    ( MonadIO handler
    , AddHeader "Location" Link NoContent withLocation
    , Rerouteable route
    )
  => handler withLocation
reroute = reroute' @route @route

-- | Redirect to 'route' as 'reroute'.
--
-- This generates the redirect link if the supplied servant 'route' is
-- a valid route in the supplied 'api'.
reroute'
  :: forall (api :: Type) (route :: Type) handler withLocation .
    ( MonadIO handler
    , Rerouteable' route api
    , AddHeader "Location" Link NoContent withLocation
    )
  => handler withLocation
reroute' = redirect $ Proxy @api `safeLink` Proxy @route

--------------------------------------------------
-- * Specializations
--------------------------------------------------

-- | A specialization of 'reroute'
rerouteCookie
  :: forall (route :: Type) (method :: StdMethod) handler .
    ( MonadIO handler
    , Rerouteable route
    )
  => ServerT (AuthCookieRedirect method Link) handler
rerouteCookie = reroute @route
