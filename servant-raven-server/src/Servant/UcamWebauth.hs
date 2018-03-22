{-|
Module      : Servant.UcamWebauth
Description : Authenticate using the Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

This module implements the client form of the University of Cambridge’s Ucam-Webauth protocol,
as in the link below. The protocol is a handshake between the

  [@WAA@], /i.e./ application wishing to authenticate (whatever uses this module!), and the
  [@WLS@], /i.e./ server which can authenticate the user

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

See the "Servant.Raven.Auth" module for a specific implementation, and
"Servant.Raven.Example" for an example.

It is necessary to store the relevant public keys.
These are provided as PEM self-signed certificates in the ‘static’ directory, named

@pubkey\//key/.crt@

where @/key/@ should be replaced by the 'KeyID' /e.g./ @pubkey2.crt@

This module provides functions which operate in any 'MonadIO' servant handler, as opposed to just 'Handler'.
They work best with handlers for which 'UnliftIO' (from "unliftio-core") is implemented.

-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , DataKinds
  , FlexibleContexts
  , FlexibleInstances
  , NamedFieldPuns
  , OverloadedStrings
  , PartialTypeSignatures
  , RankNTypes
  , RecordWildCards
  , ScopedTypeVariables
  , TypeApplications
  , TypeFamilies
  , TypeInType
  , TypeOperators
  #-}

module Servant.UcamWebauth
  (
  -- * Handlers
  -- $handlers
    ucamWebauthCookie
  , ucamWebauthToken
  -- ** Helpers
  , ucamWebauthAuthenticate
  , servantMkJWT

  -- * Configuration
  -- ** Authentication arguments
  , AuthenticationArgs
  , authJWK
  , authTokCreate
  , authWAASettings
  , authExpires
  , authenticationArgs

  -- * Reexports
  -- ** Endpoints
  , UcamWebauthCookie
  , UcamWebauthToken
  -- ** Wrappers
  , Cookied
  , Base64UBSL
  -- ** Settings
  , ucamWebauthSettings
  , authURI
  ) where

import           "errors"              Control.Error
import           "base"                Control.Monad.IO.Class
import           "mtl"                 Control.Monad.State
import           "jose"                Crypto.JOSE.JWK (JWK)
import           "aeson"               Data.Aeson.Types hiding ((.=))
import           "ucam-webauth-types"  Data.ByteString.B64
import           "time"                Data.Time
import           "microlens"           Lens.Micro
import           "microlens-mtl"       Lens.Micro.Mtl
import           "servant-server"      Servant
import           "servant-auth-server" Servant.Auth.Server
import           "servant-auth-server" Servant.Auth.Server.SetCookieOrphan ()
import           "servant-raven"       Servant.UcamWebauth.API
import           "servant-raven"       Servant.UcamWebauth.Settings
import           "ucam-webauth"        UcamWebauth
import qualified "unliftio"            UnliftIO.Exception as UIO

------------------------------------------------------------------------------
--
-- * Top level functions

-- | UcamWebauthInfo can be converted directly to a JWT.
instance ToJSON a => ToJWT (UcamWebauthInfo a)
-- | UcamWebauthInfo can be converted directly from a JWT.
instance FromJSON a => FromJWT (UcamWebauthInfo a)

--------------------------------------------------
-- * Authentication arguments
--------------------------------------------------

data AuthenticationArgs handler tok a = AuthenticationArgs
  { _authJWK         :: JWK
  , _authExpires     :: Maybe UTCTime
  , _authTokCreate   :: UcamWebauthInfo a -> handler tok
  , _authWAASettings :: SetWAA a
  }

-- | The 'JWK'.
authJWK :: AuthenticationArgs handler tok a `Lens'` JWK
authJWK f AuthenticationArgs{..} = (\_authJWK -> AuthenticationArgs{_authJWK, ..}) <$> f _authJWK
{-# INLINE authJWK #-}

-- | The token expiry time, to be passed to the "servant-auth" machinery.
authExpires :: AuthenticationArgs handler tok a `Lens'` Maybe UTCTime
authExpires f AuthenticationArgs{..} = (\_authExpires -> AuthenticationArgs{_authExpires, ..}) <$> f _authExpires
{-# INLINE authExpires #-}

-- | A function to create a token from the 'UcamWebauthInfo a' recovered
-- from the WLS-Response.
authTokCreate :: AuthenticationArgs handler tok a `Lens'` (UcamWebauthInfo a -> handler tok)
authTokCreate f AuthenticationArgs{..} = (\_authTokCreate -> AuthenticationArgs{_authTokCreate, ..}) <$> f _authTokCreate
{-# INLINE authTokCreate #-}

-- | Settings for the WAA.
authWAASettings :: AuthenticationArgs handler tok a `Lens'` SetWAA a
authWAASettings f AuthenticationArgs{..} = (\_authWAASettings -> AuthenticationArgs{_authWAASettings, ..}) <$> f _authWAASettings
{-# INLINE authWAASettings #-}

-- | Produce a default configuration.
--
-- > authenticationArgs ky $ do
-- >   authWAASettings .= setWAA
authenticationArgs
  :: forall handler a aas .
    ( Applicative handler
    , aas ~ AuthenticationArgs handler (UcamWebauthInfo a) a
    )
  => JWK
  -> State aas ()
  -> aas
authenticationArgs _authJWK = (&~) AuthenticationArgs{..}
  where
    _authExpires   = Nothing
    _authTokCreate   = pure
    _authWAASettings = pure ()

--------------------------------------------------
-- * Handler functions
--------------------------------------------------

-- $handlers
--
-- If a GET request is made with no query parameters, redirect (303) to the authentication server.
--
-- If a GET request is made with the WLS-Response query parameter, try to
-- parse that parameter to a 'UcamWebauthInfo a', and then use that
-- parameter or throw a 401 error.

-- | Here, if a GET request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function and then return the log in token.
-- Supply 'pure' to use 'UcamWebauthInfo a' as a token.
ucamWebauthToken
  :: forall a handler tok .
     ( ToJSON a
     , ToJWT tok
     , MonadIO handler
     )
  => AuthenticationArgs handler tok a
  -> ServerT (UcamWebauthToken a tok) handler
ucamWebauthToken aas@AuthenticationArgs{..} mresponse = do
  uwi <- ucamWebauthAuthenticate _authWAASettings mresponse
  tok <- _authTokCreate uwi
  servantMkJWT aas tok

-- | Here, if a request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function and then set the log in token
-- as a cookie. Supply 'pure' to use 'UcamWebauthInfo a' as a token.
ucamWebauthCookie
  :: forall a handler tok .
     ( ToJSON a
     , ToJWT tok
     , MonadIO handler
     )
  => AuthenticationArgs handler tok a
  -> ServerT (UcamWebauthCookie a) handler
ucamWebauthCookie AuthenticationArgs{..} mresponse = do
    uwi <- ucamWebauthAuthenticate _authWAASettings mresponse
    tok <- _authTokCreate uwi
    mApplyCookies <- liftIO $ acceptLogin cookieSettings jwtCfg tok
    UIO.fromEither . note trans . fmap ($ ()) $ mApplyCookies
  where
    trans = err401 { errBody = "Token error" }
    cookieSettings = defaultCookieSettings
    jwtCfg = defaultJWTSettings _authJWK

-- | Try to parse the WLS-Response to a 'UcamWebauthInfo a', and then return that
-- parameter or throw a 401 error.
ucamWebauthAuthenticate
  :: forall a handler .
     ( ToJSON a
     , MonadIO handler
     )
  => SetWAA a
  -> Maybe (MaybeValidResponse a)
  -> handler (UcamWebauthInfo a)
ucamWebauthAuthenticate settings mresponse = do
    response <- UIO.fromEither . needToAuthenticate $ mresponse
    UIO.fromEitherIO . runExceptT . authError . authInfo settings $ response
  where
    needToAuthenticate = note err303 {errHeaders = ucamWebauthQuery settings}
    authError = withExceptT . const $ err401 { errBody = "Authentication error" }

-- | Wrap the base64 encoded 'JWT' with the type it represents.
servantMkJWT
  :: ( ToJWT tok
   , MonadIO handler
   )
  => AuthenticationArgs handler tok a
  -> tok -> handler (Base64UBSL tok)
servantMkJWT AuthenticationArgs{..} tok = UIO.fromEitherIO . runExceptT .
  bimapExceptT trans B64UL . ExceptT $ makeJWT tok jwtCfg _authExpires
  where
    trans _ = err401 { errBody = "Token error" }
    jwtCfg = defaultJWTSettings _authJWK
