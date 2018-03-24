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
  , ApplicativeDo
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
  , ViewPatterns
  #-}

module Servant.UcamWebauth
  (
  -- * Handlers
  -- $handlers
    ucamWebauthCookie
  , ucamWebauthCookieRedir
  , ucamWebauthToken
  -- ** Helpers
  , ucamWebauthAuthenticate
  , servantMkJWT

  -- * Configuration
  -- ** Authentication arguments
  , AuthSet
  , AuthenticationArgs
  , authSetWAA
  , authSetJWT
  , authSetCookie
  , authExpires
  , authTokCreate
  , authParam
  , authJWK
  , authenticationArgs

  -- * Reexports
  -- ** Endpoints
  , UcamWebauthCookie
  , UcamWebauthCookieRedir
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
import           "this"                Extra.Servant.Redirect
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

type AuthSet handler tok a = State (AuthenticationArgs handler tok a) ()

data AuthenticationArgs handler tok a = AuthenticationArgs
  { _authSetWAA    :: SetWAA a
  , _authSetJWT    :: JWTSettings
  , _authSetCookie :: CookieSettings
  , _authExpires   :: Maybe UTCTime
  , _authTokCreate :: UcamWebauthInfo a -> handler tok
  }

-- | Settings for the WAA.
--
-- To change the type, use 'authParam'.
authSetWAA :: AuthenticationArgs handler tok a `Lens'` SetWAA a
authSetWAA f AuthenticationArgs{..} = (\_authSetWAA -> AuthenticationArgs{_authSetWAA, ..}) <$> f _authSetWAA
{-# INLINE authSetWAA #-}

-- | Settings for JWTs.
authSetJWT :: AuthenticationArgs handler tok a `Lens'` JWTSettings
authSetJWT f AuthenticationArgs{..} = (\_authSetJWT -> AuthenticationArgs{_authSetJWT, ..}) <$> f _authSetJWT
{-# INLINE authSetJWT #-}

-- | Settings for cookies.
authSetCookie :: AuthenticationArgs handler tok a `Lens'` CookieSettings
authSetCookie f AuthenticationArgs{..} = (\_authSetCookie -> AuthenticationArgs{_authSetCookie, ..}) <$> f _authSetCookie
{-# INLINE authSetCookie #-}

-- | The token expiry time, to be passed to the "servant-auth" machinery.
authExpires :: AuthenticationArgs handler tok a `Lens'` Maybe UTCTime
authExpires f AuthenticationArgs{..} = (\_authExpires -> AuthenticationArgs{_authExpires, ..}) <$> f _authExpires
{-# INLINE authExpires #-}

-- | A function to create a token from the 'UcamWebauthInfo a' recovered
-- from the WLS-Response.
--
-- To change the type, use 'authParam'.
authTokCreate :: AuthenticationArgs handler tok a `Lens'` (UcamWebauthInfo a -> handler tok)
authTokCreate f AuthenticationArgs{..} = (\_authTokCreate -> AuthenticationArgs{_authTokCreate, ..}) <$> f _authTokCreate
{-# INLINE authTokCreate #-}

-- | Set the token function and change the WAA settings.
--
-- This lens changes the type of 'AuthenticationArgs'.
authParam :: Lens (AuthenticationArgs handler0 tok0 a) (AuthenticationArgs handler1 tok1 b) (SetWAA a, UcamWebauthInfo a -> handler0 tok0) (SetWAA b, UcamWebauthInfo b -> handler1 tok1)
authParam f AuthenticationArgs{..} = (\(_authSetWAA, _authTokCreate) -> AuthenticationArgs{_authSetWAA, _authTokCreate, ..}) <$> f (_authSetWAA, _authTokCreate)

-- | The 'JWK'.
authJWK :: AuthenticationArgs handler tok a `Lens'` JWK
authJWK = authSetJWT . \f JWTSettings{..} -> (\_key -> JWTSettings{key = _key, ..}) <$> f key
{-# INLINE authJWK #-}

-- | Produce a default configuration.
--
-- This should not be needed by users of this library, as all functions that
-- require these arguments take an 'AuthSet …'.
--
-- > authenticationArgs $ do
-- >   authSetWAA .= setWAA
authenticationArgs
  :: AuthSet handler tok a
  -> AuthenticationArgs handler tok a
authenticationArgs = (&~) AuthenticationArgs{..}
  where
    _authSetWAA    = pure ()
    _authSetJWT    = defaultJWTSettings $ error "Must set a key"
    _authSetCookie = defaultCookieSettings
    _authExpires   = Nothing
    _authTokCreate = error "Must set a token generator"

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
  => AuthSet handler tok a
  -> ServerT (UcamWebauthToken a tok) handler
ucamWebauthToken aass@(authenticationArgs -> aas) mresponse = do
    uwi <- ucamWebauthAuthenticate (aas ^. authSetWAA) mresponse
    tok <- aas ^. authTokCreate $ uwi
    servantMkJWT aass tok

-- | Here, if a request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function and then set the log in token
-- as a cookie. Supply 'pure' to use 'UcamWebauthInfo a' as a token.
ucamWebauthCookie
  :: forall a handler tok .
     ( ToJSON a
     , ToJWT tok
     , MonadIO handler
     )
  => AuthSet handler tok a
  -> ServerT (UcamWebauthCookie a) handler
ucamWebauthCookie = ucamWebauthCookie' NoContent

-- | Here, if a request is made with a valid WLS-Response query parameter, convert the
-- 'UcamWebauthInfo a' to the token type using the supplied function, set the log in token
-- as a cookie and then redirect to the location given by 'route'.
ucamWebauthCookieRedir
  :: forall route a handler tok .
     ( ToJSON a
     , ToJWT tok
     , MonadIO handler
     , Rerouteable route
     )
  => AuthSet handler tok a
  -> ServerT (UcamWebauthCookieRedir a Link) handler
ucamWebauthCookieRedir a m = do
  rerouted <- reroute @route
  ucamWebauthCookie' rerouted a m

ucamWebauthCookie'
  :: forall api content a handler tok withOneCookie .
     ( ToJSON a
     , ToJWT tok
     , MonadIO handler
     , api ~ UcamWebauthAuthenticate Cookie a (Get '[PlainText] content)
     , AddHeader "Set-Cookie" SetCookie content withOneCookie
     , AddHeader "Set-Cookie" SetCookie withOneCookie (Cookied content)
     )
  => content
  -> AuthSet handler tok a
  -> ServerT api handler
ucamWebauthCookie' content (authenticationArgs -> aas) mresponse = do
    uwi <- ucamWebauthAuthenticate (aas ^. authSetWAA) mresponse
    tok <- aas ^. authTokCreate $ uwi
    applyCookies <- UIO.fromEither . note trans <=< liftIO $
      acceptLogin @_ @_ @_ @(Cookied content) (aas ^. authSetCookie) (aas ^. authSetJWT) tok
    pure $ applyCookies content
  where
    trans = err401 { errBody = "Token error" }

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
  => AuthSet handler tok a
  -> tok -> handler (Base64UBSL tok)
servantMkJWT (authenticationArgs -> aas) tok = UIO.fromEitherIO . runExceptT .
  bimapExceptT trans B64UL . ExceptT $ makeJWT tok (aas ^. authSetJWT) (aas ^. authExpires)
  where
    trans _ = err401 { errBody = "Token error" }
