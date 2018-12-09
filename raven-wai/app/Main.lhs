---
title:  Example use of raven-wai  
author: David Baynard  
date:   12 May 2017  
fontfamily:   libertine
csl:    chemical-engineering-science.csl
link-citations: true
abstract: |  
    
...

```haskell
{-|
Module      : Network.Wai.Protocol.Raven.Example
Description : Example use of Wai Raven authentication (test)
Maintainer  : David Baynard <ucamwebauth@baynard.me>

-}
```

```haskell
{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , OverloadedStrings
  , ScopedTypeVariables
  , TypeApplications
  , TypeFamilies
  #-}

module Main
 ( main
 ) where

import           "base"          Control.Applicative
import           "errors"        Control.Error
import           "base"          Control.Monad
import           "mtl"           Control.Monad.State
import           "aeson"         Data.Aeson.Types (FromJSON)
import           "bytestring"    Data.ByteString (ByteString)
import           "bytestring"    Data.ByteString.Builder
import           "text"          Data.Text (Text)
import qualified "text"          Data.Text.IO as T
import           "time"          Data.Time (UTCTime, getCurrentTime)
import           "microlens"     Lens.Micro
import           "microlens-mtl" Lens.Micro.Mtl
import           "http-types"    Network.HTTP.Types
import           "wai"           Network.Wai
import           "warp"          Network.Wai.Handler.Warp
import           "ucam-webauth"  UcamWebauth

import Network.Wai.Protocol.Raven.Test
import Network.Wai.Protocol.UcamWebauth

main :: IO ()
main = warpit

warpit :: IO ()
warpit = run 3000 . application =<< getCurrentTime

application :: UTCTime -> Application
application time req response = case pathInfo req of
  ["foo", "bar"] -> response $ responseBuilder
    status200
    [("Content-Type", "text/plain")]
    (byteString "You requested /foo/bar")
  ["foo", "rawquery"] -> response $ responseBuilder
    status200
    [("Content-Type", "text/plain")]
    (byteString . rawQueryString $ req)
  ["foo", "query"] -> response . responseBuilder
    status200
    [("Content-Type", "text/plain")]
    =<< displayAuthInfo req 
  ["foo", "queryAll"] -> response . responseBuilder
    status200
    [("Content-Type", "text/plain")]
    =<< displayWLSResponse @Text req 
  ["foo", "queryR"] -> response $ responseBuilder
    status200
    [("Content-Type", "text/plain")]
    (displayWLSQuery req)
```

``` { .haskell .ignore }
  ["foo", "requestHeaders"] -> response $ responseBuilder
    status200
    [("Content-Type", "text/plain")]
    (_ . requestHeaders $ req)
```

```haskell
  ["foo", "authenticate"] -> response $ responseBuilder
    seeOther303
    (("Content-Type", "text/plain") : ucamWebauthQuery settings)
    mempty
  _ -> response $ responseBuilder
    status200
    [("Content-Type", "text/plain")]
    (byteString "You requested something else")
  where
    settings = do
      mySettings
      wSet . recentTime .= time
      aReq . ucamQDate .= pure time

displayWLSQuery :: Request -> Builder
displayWLSQuery = maybe mempty byteString . lookUpWLSResponse

displayAuthInfo :: Request -> IO Builder
displayAuthInfo = displayAuthResponse <=< liftMaybe . lookUpWLSResponse

displayWLSResponse :: forall a . (FromJSON a, Show a) => Request -> IO Builder
displayWLSResponse = displayAuthResponseFull @a <=< liftMaybe . lookUpWLSResponse

displayAuthResponseFull :: forall a . (FromJSON a, Show a) => ByteString -> IO Builder
displayAuthResponseFull = displaySomethingAuthy . authCode @a

displayAuthResponse :: ByteString -> IO Builder
displayAuthResponse = displaySomethingAuthy . maybeAuthInfo mySettings

```

Produce the request to the authentication server as a response

```haskell
mySettings :: SetWAA Text
mySettings = do
  ravenSettings
  wSet . applicationUrl .= "http://localhost:3000/foo/query"
  waa <- get
  aReq . ucamQUrl .= waa ^. wSet . applicationUrl
  aReq . ucamQDesc .= pure "This is a sample; it’s rather excellent!"
  aReq . ucamQAauth .= pure (waa ^. wSet . authAccepted)
  aReq . ucamQIact .= waa ^. wSet . needReauthentication
  aReq . ucamQMsg .= pure "This is a private resource, or something."
  aReq . ucamQParams .= pure "This is 100% of the data! And it’s really quite cool"
  aReq . ucamQDate .= pure (waa ^. wSet . recentTime)
  aReq . ucamQFail .= empty

displaySomethingAuthy
  :: forall b m .
    ( m ~ (ExceptT Text IO) -- m ~ ReaderT (SetAuthRequest a) (MaybeT IO)
    , Show b
    )
  -- , a ~ Text )
  -- => SetWAA a
  => m b
  -> IO Builder
displaySomethingAuthy = exceptT (const empty . T.putStrLn) (pure . stringUtf8 . show)
            -- . uncurry runReaderT
```

Helper

```haskell
liftMaybe :: Alternative f => Maybe a -> f a
liftMaybe = maybe empty pure
```
