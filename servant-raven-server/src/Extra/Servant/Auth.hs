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
  ( authenticated
  , authenticatedProxied
  , throwAll'
  , throwAllProxied
  ) where

import           "base"                Control.Monad.IO.Class
import           "base"                Data.Kind
import           "servant-auth-server" Servant.Auth.Server
import           "servant-server"      Servant
import qualified "unliftio"            UnliftIO.Exception as UIO

type WithAuthenticated (api :: Type) (m :: Type -> Type) =
  ( HasServer api '[]
  , ThrowAll (Server api)
  , MonadIO m
  )

-- | Wrap the provided handler function with authentication.
authenticated
  :: forall api m u . WithAuthenticated api m
  => (u -> ServerT api m)
  -> AuthResult u
  -> ServerT api m
authenticated f (Authenticated user) = f user
authenticated _ _ = throwAll' @api @m err401

-- | Wrap the provided handler function with authentication.
authenticatedProxied
  :: forall api m u . WithAuthenticated api m
  => Proxy api
  -> (u -> ServerT api m)
  -> AuthResult u
  -> ServerT api m
authenticatedProxied _ = authenticated @api @m

throwAll'
  :: forall api m . WithAuthenticated api m
  => ServantErr
  -> ServerT api m
throwAll' = hoistServer @api @_ @m Proxy (UIO.fromEitherIO . runHandler) . throwAll @(Server api)

throwAllProxied
  :: forall api m . WithAuthenticated api m
  => Proxy api
  -> Proxy m
  -> ServantErr
  -> ServerT api m
throwAllProxied _ _ = throwAll' @api @m

