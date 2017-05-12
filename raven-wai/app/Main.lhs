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
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}
```

```haskell
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (
    main
)   where

-- Prelude
import "errors" Control.Error
import "time" Data.Time (UTCTime, getCurrentTime)
import "base" Control.Monad
import "base" Control.Applicative
import "mtl" Control.Monad.State

import "microlens" Lens.Micro
import "microlens-mtl" Lens.Micro.Mtl

-- The protocol
import Network.Wai.Protocol.UcamWebauth
import Network.Wai.Protocol.Raven.Test

-- Wai and http protocol
import "wai" Network.Wai
import "http-types" Network.HTTP.Types

-- ByteString building
import "text" Data.Text (Text)
import "bytestring" Data.ByteString (ByteString)
import "bytestring" Data.ByteString.Builder

-- Warp server
import "warp" Network.Wai.Handler.Warp

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
        =<< displayWLSResponse req 
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
        [("Content-Type", "text/plain"), ucamWebauthQuery settings]
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

displayWLSResponse :: Request -> IO Builder
displayWLSResponse = displayAuthResponseFull <=< liftMaybe . lookUpWLSResponse

displayAuthResponseFull :: ByteString -> IO Builder
displayAuthResponseFull = displaySomethingAuthy . maybeAuthCode mySettings

displayAuthResponse :: ByteString -> IO Builder
displayAuthResponse = displaySomethingAuthy . maybeAuthInfo mySettings

{-|
  Produce the request to the authentication server as a response
-}
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


displaySomethingAuthy :: forall b m
                        . ( m ~ (MaybeT IO) -- m ~ ReaderT (SetAuthRequest a) (MaybeT IO)
                          , Show b
                          )
                          -- , a ~ Text )
                       -- => SetWAA a
                       => m b
                       -> IO Builder
displaySomethingAuthy = maybeT empty (pure . stringUtf8 . show)
                        -- . uncurry runReaderT

```

