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

module Servant.UcamWebauth (
    module Servant.UcamWebauth
  , module X
)   where

-- Prelude
import "Ucam-Webauth" Network.Protocol.UcamWebauth as X

import "base" GHC.Generics
import "base" Control.Monad.IO.Class
import "base" Data.Kind
import "base" Control.Monad

import "mtl" Control.Monad.Except

import "text" Data.Text (Text)

import "servant-server" Servant
import "servant-auth-server" Servant.Auth.Server
import "servant-auth-server" Servant.Auth.Server.SetCookieOrphan ()
import "jose" Crypto.JOSE.JWK (JWK)

import "aeson" Data.Aeson.Types hiding ((.=))
-- Map structures

newtype User = User Text
    deriving (Eq, Show, Read, Generic)

instance ToJSON User
instance ToJWT User
instance FromJSON User
instance FromJWT User

type Protected
    = "user" :> Get '[JSON] Text

protected :: ThrowAll (Handler protected) => (a -> Handler protected) -> AuthResult a -> Handler protected
protected f (Authenticated user) = f user
protected _ _ = throwAll err401

type Raven a
    = "raven" :> Get '[JSON] (UcamWebauthInfo a)
    :<|> "authenticate" :> QueryParam "WLS-Response" (SignedAuthResponse 'MaybeValid a) :> Get '[JSON] (UcamWebauthInfo a)

raven :: ToJSON a => SetWAA a -> Server (Raven a)
raven settings = throwError err303 {errHeaders = [ucamWebauthQuery settings]}
    :<|> Handler . ravenError . (authInfo settings <=< liftMaybe)
        where
            ravenError = withExceptT . const $ err401 { errBody = "Raven error" }

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
    :<|> Raven a
    :<|> Unprotected

server :: ToJSON a => SetWAA a -> CookieSettings -> JWTSettings -> Server (API auths a)
server rs cs jwts =
        protected (return . (\(User user) -> user))
    :<|> raven rs
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
        Proxy @(API auths a) `serveWithContext` cfg $ server rs defaultCookieSettings jwtCfg
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

------------------------------------------------------------------------------
--
-- * Top level functions
