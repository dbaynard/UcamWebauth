{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , ConstraintKinds
  , DataKinds
  , FlexibleContexts
  , ScopedTypeVariables
  , TypeApplications
  , TypeInType
  , TypeOperators
  #-}

module Extra.Servant.Auth
  ( WithAuthenticated
  , authenticated
  , authenticatedProxied
  , throwAll'
  , throwAllProxied
  ) where

import           "base"                Control.Monad.IO.Class
import           "base"                Data.Kind
import           "servant-server"      Servant
import           "servant-auth-server" Servant.Auth.Server
import qualified "unliftio"            UnliftIO.Exception as UIO

-- | Constraints for authenticated endpoints
type WithAuthenticated (api :: Type) (context :: [Type]) (handler :: Type -> Type) =
  ( HasServer api context
  , ThrowAll (Server api)
  , MonadIO handler
  )

-- | Wrap the provided handler function with authentication.
authenticated
  :: forall api context m u . WithAuthenticated api context m
  => (u -> ServerT api m)
  -> AuthResult u
  -> ServerT api m
authenticated = authenticatedProxied @api @context @m Proxy Proxy

-- | Wrap the provided handler function with authentication.
authenticatedProxied
  :: forall api context m u . WithAuthenticated api context m
  => Proxy api
  -> Proxy context
  -> (u -> ServerT api m)
  -> AuthResult u
  -> ServerT api m
authenticatedProxied _ _ f (Authenticated user) = f user
authenticatedProxied api context _ _ = throwAllProxied api context (Proxy @m) err401

-- | Throw an error throughout an api.
throwAll'
  :: forall api context m . WithAuthenticated api context m
  => ServantErr
  -> ServerT api m
throwAll' = throwAllProxied @api @context @m Proxy Proxy Proxy

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
  throwAll @(Server api)

