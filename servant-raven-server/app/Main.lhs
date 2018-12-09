---
title:  Authenticating using Servant and Raven  
author: David Baynard  
date:   15 May 2017  
fontfamily:   libertine
csl:    chemical-engineering-science.csl
link-citations: true
abstract: |  
    
...

```haskell
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , OverloadedStrings
  , AllowAmbiguousTypes
  , DataKinds
  , DeriveGeneric
  , FlexibleContexts
  , InstanceSigs
  , QuasiQuotes
  , RankNTypes
  , RecordWildCards
  , ScopedTypeVariables
  , TypeApplications
  , TypeFamilies
  , TypeInType
  , TypeOperators
  #-}

module Main where

import           "base"                Control.Applicative
import           "base"                Control.Concurrent
import           "errors"              Control.Error
import           "base"                Control.Monad
import           "mtl"                 Control.Monad.Except
import qualified "unliftio-core"       Control.Monad.IO.Unlift as UIO
import           "mtl"                 Control.Monad.State
import           "jose"                Crypto.JOSE
import           "bytestring"          Data.ByteString (ByteString)
import           "base"                Data.Kind
import           "base"                Data.Proxy
import           "reflection"          Data.Reflection
import           "text"                Data.Text (Text)
import qualified "text"                Data.Text as T
import           "text"                Data.Text.Encoding
import qualified "text"                Data.Text.IO as T
import           "time"                Data.Time
import           "yaml"                Data.Yaml hiding ((.=))
import           "microlens"           Lens.Micro
import           "microlens-mtl"       Lens.Micro.Mtl
import           "warp"                Network.Wai.Handler.Warp
import           "wai-extra"           Network.Wai.Middleware.RequestLogger
import           "optparse-generic"    Options.Generic
import           "servant-server"      Servant
import           "servant-auth"        Servant.Auth
import           "servant-auth-server" Servant.Auth.Server
import           "servant-raven"       Servant.Raven.Test
import           "uri-bytestring"      URI.ByteString.QQ
import           "ucam-webauth"        UcamWebauth
import qualified "unliftio"            UnliftIO.Exception as UIO

import Extra.Servant.Auth
import Servant.UcamWebauth
```

```haskell
main :: IO ()
main = do
  mainWithCookies
```

Display authentication information from the WLS response.

```haskell
displayAuth :: IO ()
displayAuth = do
    (resp :: ByteString) <- getRecord "Display authentication information"
    exceptT T.putStrLn (T.putStrLn . decodeUtf8) $ encode <$> maybeAuthInfo mySettings resp
```

Fork the server and allow new tokens to be created in the command line for the specified crsid.

```haskell
mainWithJWT :: IO ()
mainWithJWT = do
  -- We generate the key for signing tokens. This would generally be persisted,
  -- and kept safely
  ky <- generateKey
  _ <- forkIO $ launch @'[JWT] ky 7249

  T.putStrLn "Started server on localhost:7249"
  T.putStrLn "Enter crsid for a new token"

  forever $ do
    xs <- T.words <$> T.getLine
    case xs of
      [crsid] -> tokenise ky crsid
      _ -> T.putStrLn "Just enter a crsid"

mainWithCookies :: IO ()
mainWithCookies = do
  -- We *also* need a key to sign the cookies
  ky <- generateKey
  -- Adding some configurations. 'Cookie' requires, in addition to
  -- CookieSettings, JWTSettings (for signing), so everything is just as before
  launch @'[Cookie] ky 7249

launch
  :: forall (auths :: [Type]) .
    ( AreAuths auths '[CookieSettings, JWTSettings] User
    )
  => JWK -> Int -> IO ()
launch ky port = do
    t <- getCurrentTime
    run port . logStdoutDev . serveWithAuth @auths ky . settings $ t
  where
    settings time = do
      mySettings
      wSet . recentTime .= time
      aReq . ucamQDate .= pure time

exampleResponse :: ByteString
exampleResponse = "3!200!!20170515T172311Z!oANAuhC9fZmMlZUPIm53y5vn!http://localhost:3000/foo/query!test0244!current!!pwd!30380!IlRoaXMgaXMgMTAwJSBvZiB0aGUgZGF0YSEgQW5kIGl04oCZcyByZWFsbHkgcXVpdGUgY29vbCI_!901!RzC9KZWALCSeK0n9885X4zzemHizuj8K.NOpt.n1hfRCTE2ZBgvJ-fBvT-PaL80cSFGpyCJgt9LvM4-peJzcidoKC6zhBEvG0QnlqWTLsphbIA0JmBRiOoeqyLYRVGwDEdLdacdsQRM.u7bik.enhbuN1-aIQCOdB5MutxtYiu4_"

mySettings :: forall (auths :: [Type]) api . (api ~ API auths Text) => SetWAA Text
mySettings = [uri|http://127.0.0.1:7249|] `reify` \(Proxy :: Proxy baseurl) -> do
    ravenSettings @baseurl @api @(Raven Text)
    waa <- get
    aReq . ucamQUrl .= waa ^. wSet . applicationUrl
    aReq . ucamQDesc .= pure "This is a sample; it’s rather excellent!"
    aReq . ucamQAauth .= pure (waa ^. wSet . authAccepted)
    aReq . ucamQIact .= waa ^. wSet . needReauthentication
    aReq . ucamQMsg .= pure "This is a private resource, or something."
    aReq . ucamQParams .= pure "This is 100% of the data! And it’s really quite cool"
    aReq . ucamQDate .= pure (waa ^. wSet . recentTime)
    aReq . ucamQFail .= empty

------------------------------------------------------------------------------

```

```haskell
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

type Raven a = "authenticate" :> UcamWebauthToken a (UcamWebauthInfo a)

type API auths a
    = Auth auths User :> Protected
 :<|> Raven a
 :<|> Unprotected

server :: ToJSON a => SetWAA a -> CookieSettings -> JWTSettings -> JWK -> Server (API auths a)
server rs cs jwts ky
    = authenticated @Protected (pure . (\(User user) -> user))
 :<|> ucamWebauthToken (do authSetWAA .= rs; authTokCreate .= pure; authJWK .= ky)
 :<|> unprotected cs jwts

-- Auths may be '[JWT] or '[Cookie] or even both.
serveWithAuth
  :: forall (auths :: [Type]) a context .
    ( AreAuths auths context User
    , context ~ '[CookieSettings, JWTSettings]
    , ToJSON a
    , FromJSON a
    )
  => JWK -> SetWAA a -> Application
serveWithAuth ky rs =
    Proxy @(API auths a) `serveWithContext` cfg $
      hoistS @(API auths a) @context servantErr $
      server rs defaultCookieSettings jwtCfg ky
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

```

## Catching servant exceptions

```haskell
instance UIO.MonadUnliftIO Handler where
  withRunInIO :: ((forall a . Handler a -> IO a) -> IO b) -> Handler b
  -- f :: (forall a . Handler a -> IO a) -> IO b
  -- f unHandle :: IO b
  withRunInIO f = Handler . ExceptT . UIO.tryJust (UIO.fromException @ServantErr) $ f unHandle

servantErr :: forall a . Handler a -> Handler a
servantErr = UIO.fromException @ServantErr `UIO.handleJust` (Handler . throwError)

unHandle :: forall a . Handler a -> IO a
unHandle = UIO.fromEitherIO . runHandler

hoistS
  :: forall api context m . HasServer api context
  => (forall x . m x -> Handler x)
  -> ServerT api m
  -> Server api
hoistS f = Proxy @api `hoistServerWithContext` Proxy @context $ servantErr . f
```
