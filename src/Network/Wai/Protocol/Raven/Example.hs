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
        [("Content-Type", "text/plain"), ucamWebauthQuery ravenAuth . ucamWebauthHello $ mySettings >> recentTime .= time]
        mempty
    _ -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")

displayWLSQuery :: Request -> BlazeBuilder
displayWLSQuery = maybe mempty Z.fromShow . lookUpWLSResponse

displayAuthInfo :: Request -> IO BlazeBuilder
displayAuthInfo = displayAuthResponse <=< liftMaybe . lookUpWLSResponse

displayWLSResponse :: Request -> IO BlazeBuilder
displayWLSResponse = displayAuthResponseFull <=< liftMaybe . lookUpWLSResponse

displayAuthResponseFull :: ByteString -> IO BlazeBuilder
displayAuthResponseFull = displaySomethingAuthy mySettings . maybeAuthCode mySettings

displayAuthResponse :: ByteString -> IO BlazeBuilder
displayAuthResponse = displaySomethingAuthy mySettings . maybeAuthInfo mySettings

displaySomethingAuthy :: (m ~ ReaderT (AuthRequest a) (MaybeT IO), Show b, a ~ Text) => SetWAA -> m b -> IO BlazeBuilder
displaySomethingAuthy = flip . curry $ maybeT empty (pure . Z.fromShow) . uncurry runReaderT . second ucamWebauthHello

ucamWebauthHello :: (ToJSON a, IsString a, a ~ Text) => SetWAA -> AuthRequest a
ucamWebauthHello mkConfig = AuthRequest {
                  _ucamQVer = WLS3
                , _ucamQUrl = viewConfigWAA applicationUrl mkConfig
                , _ucamQDesc = Just "This is a sample; it’s rather excellent!"
                , _ucamQAauth = pure . viewConfigWAA authAccepted $ mkConfig
                , _ucamQIact = viewConfigWAA needReauthentication mkConfig
                , _ucamQMsg = Just "This is a private resource, or something."
                , _ucamQParams = Just "This is 100% of the data! And it’s really quite cool"
                , _ucamQDate = pure . viewConfigWAA recentTime $ mkConfig
                , _ucamQFail = empty
                }

{-|
  Produce the request to the authentication server as a response
-}
mySettings :: SetWAA
mySettings = do
        ravenSettings
        applicationUrl .= "http://localhost:3000/foo/query"

