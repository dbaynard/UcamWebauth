{-|
Module      : Network.Wai.Protocol.Raven.Example
Description : Example use of Wai Raven authentication (test)
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Wai.Protocol.Raven.Example (
    module Network.Wai.Protocol.Raven.Example
)   where

-- Prelude
import ClassyPrelude

import Control.Error

-- The protocol
import Network.Wai.Protocol.UcamWebauth
import Network.Wai.Protocol.Raven.Test

-- Wai and http protocol
import Network.Wai
import Network.HTTP.Types

-- JSON
import Data.Aeson (ToJSON)

-- ByteString building
import Blaze.ByteString.Builder hiding (Builder)
import qualified Blaze.ByteString.Builder.Char.Utf8 as Z

-- Warp server
import Network.Wai.Handler.Warp

warpit :: IO ()
warpit = run 3000 . application =<< getCurrentTime

application :: UTCTime -> Application
application time req response = case pathInfo req of
    ["foo", "bar"] -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested /foo/bar")
    ["foo", "rawquery"] -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString . rawQueryString $ req)
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
    ["foo", "requestHeaders"] -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (Z.fromShow . requestHeaders $ req)
    ["foo", "authenticate"] -> response $ responseBuilder
        seeOther303
        [("Content-Type", "text/plain"), ucamWebauthQuery settings]
        mempty
    _ -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")
    where
        settings = do
            mySettings
            wSet . recentTime .= time
            aReq . ucamQDate .= pure time

displayWLSQuery :: Request -> BlazeBuilder
displayWLSQuery = maybe mempty Z.fromShow . lookUpWLSResponse

displayAuthInfo :: Request -> IO BlazeBuilder
displayAuthInfo = displayAuthResponse <=< liftMaybe . lookUpWLSResponse

displayWLSResponse :: Request -> IO BlazeBuilder
displayWLSResponse = displayAuthResponseFull <=< liftMaybe . lookUpWLSResponse

displayAuthResponseFull :: ByteString -> IO BlazeBuilder
displayAuthResponseFull = displaySomethingAuthy . maybeAuthCode mySettings

displayAuthResponse :: ByteString -> IO BlazeBuilder
displayAuthResponse = displaySomethingAuthy . maybeAuthInfo mySettings

{-|
  Produce the request to the authentication server as a response
-}
mySettings :: (ToJSON a, IsString a, a ~ Text) => SetWAA a
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
                          , Show b )
                          -- , a ~ Text )
                       -- => SetWAA a
                       => m b
                       -> IO BlazeBuilder
displaySomethingAuthy = maybeT empty (pure . Z.fromShow)
                        -- . uncurry runReaderT

