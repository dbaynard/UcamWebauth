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

It is necessary to store the relevant public keys, as described in the documentation
for 'readRSAKeyFile'.

-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeInType #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Servant.UcamWebauth (
    module Servant.UcamWebauth
  , module X
)   where

-- Prelude
import "Ucam-Webauth" Network.Protocol.UcamWebauth as X

import "base" GHC.Generics
import "base" Control.Monad.IO.Class
import "base" Data.Kind

import "errors" Control.Error

import "text" Data.Text (Text)

import "time" Data.Time

import "servant-server" Servant
import "servant-auth-server" Servant.Auth.Server
import "servant-auth-server" Servant.Auth.Server.SetCookieOrphan ()
import "jose" Crypto.JOSE.JWK (JWK)

import "aeson" Data.Aeson.Types hiding ((.=))

------------------------------------------------------------------------------
--
-- * Top level functions

-- | Base 64 (URL) encoded 'ByteString's should be serializable as 'OctetStream's.
-- They are already serializable as 'JSON' thanks to the ToJson instance.
instance MimeRender OctetStream Base64UBSL where
    mimeRender _ = unB64UL

-- TODO Make safe
instance MimeUnrender OctetStream Base64UBSL where
    mimeUnrender _ = pure . B64UL

-- | UcamWebauthInfo can be converted directly to a JWT.
instance ToJSON a => ToJWT (UcamWebauthInfo a)
-- | UcamWebauthInfo can be converted directly from a JWT.
instance FromJSON a => FromJWT (UcamWebauthInfo a)

-- | Wrap the provided handler function with authentication.
authenticated
    :: ThrowAll (Handler protected)
    => (a -> Handler protected)
    -> AuthResult a
    -> Handler protected
authenticated f (Authenticated user) = f user
authenticated _ _ = throwAll err401

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthenticate a
    = QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[JSON] (UcamWebauthInfo a)

-- | If a GET request is made with no query parameters, redirect (303) to the authentication server.
--
-- If a GET request is made with the WLS-Response query parameter, try to
-- parse that parameter to a 'UcamWebauthInfo a', and then return that
-- parameter or throw a 401 error.
ucamWebAuthenticate
    :: forall a. ToJSON a
    => SetWAA a
    -> Maybe (SignedAuthResponse 'MaybeValid a)
    -> Handler (UcamWebauthInfo a)
ucamWebAuthenticate settings mresponse = do
        response <- Handler . needToAuthenticate . liftMaybe $ mresponse
        Handler . authError . authInfo settings $ response
    where
        needToAuthenticate = noteT err303 {errHeaders = [ucamWebauthQuery settings]}
        authError = withExceptT . const $ err401 { errBody = "Authentication error" }

-- | A bifunctional endpoint for authentication, which both delegates and
-- responds to the Web Login Service (WLS).
type UcamWebAuthToken token a
    = QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[OctetStream] token

-- | Here, if a GET request is made with a valid WLS-Response query parameter, return the
-- 'UcamWebauthInfo a' as a log in token.
ucamWebAuthToken
    :: forall a. ToJSON a
    => SetWAA a
    -> Maybe UTCTime
    -> JWK
    -> Maybe (SignedAuthResponse 'MaybeValid a)
    -> Handler Base64UBSL
ucamWebAuthToken settings mexpires ky mresponse = let jwtCfg = defaultJWTSettings ky in do
        uwi <- ucamWebAuthenticate settings mresponse
        Handler . bimapExceptT trans B64UL . ExceptT $ makeJWT uwi jwtCfg mexpires
    where
        trans _ = err401 { errBody = "Token error" }

------------------------------------------------------------------------------

newtype User = User Text
    deriving (Eq, Show, Read, Generic)

instance ToJSON User
instance ToJWT User
instance FromJSON User
instance FromJWT User

type Protected
    = "user" :> Get '[JSON] Text

type Unprotected
    = "login" :> ReqBody '[JSON] (UcamWebauthInfo Text) :> PostNoContent '[JSON]
        ( Headers
           '[ Header "Set-Cookie" SetCookie
            , Header "Set-Cookie" SetCookie
            ] NoContent
        )
    :<|> Raw

unprotected :: CookieSettings -> JWTSettings -> Server Unprotected
unprotected cs jwts = checkCreds cs jwts :<|> serveDirectoryFileServer "example/static"

type API auths a
    = Auth auths User :> Protected
    :<|> "authenticate" :> UcamWebAuthToken Base64UBSL a
    :<|> Unprotected

server :: ToJSON a => SetWAA a -> CookieSettings -> JWTSettings -> JWK -> Server (API auths a)
server rs cs jwts ky =
        authenticated (return . (\(User user) -> user))
    :<|> ucamWebAuthToken rs Nothing ky
    :<|> unprotected cs jwts

-- Auths may be '[JWT] or '[Cookie] or even both.
serveWithAuth
    :: forall (auths :: [Type]) a .
        ( AreAuths auths '[CookieSettings, JWTSettings] User
        , ToJSON a
        , FromJSON a
        )
    => JWK -> SetWAA a -> Application
serveWithAuth ky rs =
        Proxy @(API auths a) `serveWithContext` cfg $ server rs defaultCookieSettings jwtCfg ky
    where
        -- Adding some configurations. All authentications require CookieSettings to
        -- be in the context.
        jwtCfg = defaultJWTSettings ky
        cfg = defaultCookieSettings :. jwtCfg :. EmptyContext

tokenise :: JWK -> Text -> IO ()
tokenise ky crsid = let jwtCfg = defaultJWTSettings ky in do
        etoken <- makeJWT (User crsid) jwtCfg Nothing
        case etoken of
            Left e -> putStrLn $ "Error generating token:\t" ++ show e
            Right v -> putStrLn $ "New token:\t" ++ show v

-- Here is the login handler
checkCreds
    :: CookieSettings
    -> JWTSettings
    -> UcamWebauthInfo Text
    -> Handler (Headers
       '[ Header "Set-Cookie" SetCookie
        , Header "Set-Cookie" SetCookie
        ] NoContent)
checkCreds cookieSettings jwtSettings _ = do
    -- Usually you would ask a database for the user info. This is just a
    -- regular servant handler, so you can follow your normal database access
    -- patterns (including using 'enter').
    let usr = User "db506"
    mApplyCookies <- liftIO $ acceptLogin cookieSettings jwtSettings usr
    case mApplyCookies of
        Nothing           -> throwError err401
        Just applyCookies -> return $ applyCookies NoContent

