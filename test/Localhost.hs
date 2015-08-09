import TestSuite

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
        [("Content-Type", "text/plain"), ucamWebauthQuery ravenAuth . ucamWebauthHello (Just "This is 100% of the data! And it’s really quite cool" :: Maybe Text) $ time]
        mempty
    _ -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")

-- TODO These 5 functions don’t work any more, possibly
displayWLSQuery :: Request -> Z.Builder
displayWLSQuery = maybe mempty Z.fromShow . lookUpWLSResponse

displayAuthInfo :: Request -> IO Z.Builder
displayAuthInfo = displayAuthResponse <=< liftMaybe . lookUpWLSResponse

displayWLSResponse :: Request -> IO Z.Builder
displayWLSResponse = displayAuthResponseFull <=< liftMaybe . lookUpWLSResponse

displayAuthResponseFull :: ByteString -> IO Z.Builder
displayAuthResponseFull = maybeT empty (pure . Z.fromShow) . maybeAuthCode

displayAuthResponse :: ByteString -> IO Z.Builder
displayAuthResponse = maybeT empty (pure . Z.fromShow) . maybeAuthInfo

ucamWebauthHello :: ToJSON a => Maybe a -> UTCTime -> AuthRequest a
ucamWebauthHello params time = AuthRequest {
                  ucamQVer = WLS3
                , ucamQUrl = urlToTransmit
                , ucamQDesc = Just "This is a sample; it’s rather excellent!"
                , ucamQAauth = authAccepted
                , ucamQIact = needReauthentication
                , ucamQMsg = Just "This is a private resource, or something."
                , ucamQParams = params
                , ucamQDate = pure time
                , ucamQFail = pure False
                }

{-|
  Produce the request to the authentication server as a response
-}
urlToTransmit :: Text
urlToTransmit = "http://localhost:3000/foo/query"

