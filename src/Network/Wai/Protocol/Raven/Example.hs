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
import Control.Applicative (empty, Alternative)
import Control.Error

-- The protocol
import Network.Wai.Protocol.UcamWebauth
import Network.Wai.Protocol.Raven.Test

-- Wai and http protocol
import Network.Wai
import Network.HTTP.Types

-- JSON
import Data.Aeson (ToJSON, FromJSON)

-- ByteString building
import Blaze.ByteString.Builder hiding (Builder)
import qualified Blaze.ByteString.Builder as Z (Builder)
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
        [("Content-Type", "text/plain"), ucamWebauthQuery ravenAuth . ucamWebauthHello $ time]
        mempty
    _ -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")

displayWLSQuery :: Request -> Z.Builder
displayWLSQuery = maybe mempty Z.fromShow . lookUpWLSResponse

displayAuthInfo :: Request -> IO Z.Builder
displayAuthInfo = displayAuthResponse <=< liftMaybe . lookUpWLSResponse

displayWLSResponse :: Request -> IO Z.Builder
displayWLSResponse = displayAuthResponseFull <=< liftMaybe . lookUpWLSResponse

displayAuthResponseFull :: ByteString -> IO Z.Builder
displayAuthResponseFull = displaySomethingAuthy ancientUTCTime . maybeAuthCode

displayAuthResponse :: ByteString -> IO Z.Builder
displayAuthResponse = displaySomethingAuthy ancientUTCTime . maybeAuthInfo

displaySomethingAuthy :: (m ~ ReaderT (AuthRequest a) (MaybeT IO), Show b, a ~ Text) => UTCTime -> m b -> IO Z.Builder
displaySomethingAuthy = flip . curry $ maybeT empty (pure . Z.fromShow) . uncurry runReaderT . second ucamWebauthHello

ucamWebauthHello :: (ToJSON a, IsString a, a ~ Text) => UTCTime -> AuthRequest a
ucamWebauthHello time = AuthRequest {
                  ucamQVer = WLS3
                , ucamQUrl = urlToTransmit
                , ucamQDesc = Just "This is a sample; it’s rather excellent!"
                , ucamQAauth = authAccepted
                , ucamQIact = needReauthentication
                , ucamQMsg = Just "This is a private resource, or something."
                , ucamQParams = Just "This is 100% of the data! And it’s really quite cool"
                , ucamQDate = pure time
                , ucamQFail = pure False
                }

{-|
  Produce the request to the authentication server as a response
-}
urlToTransmit :: Text
urlToTransmit = "http://localhost:3000/foo/query"

