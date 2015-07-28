{-|
Module      : Ucam-Webauth
Description : Authenticate with the University of Cambridge protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

https://raven.cam.ac.uk/project/waa2wls-protocol.txt

-}

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module UcamWebauth (
    module UcamWebauth
)   where

import Import.NoFoundation hiding (take)
import Network.HTTP.Types
import Network.Wai
import qualified Network.Wai as W
import Network.Wai.Parse
import Data.Time.RFC3339
import Data.Time.LocalTime
import qualified Data.ByteString.Base64 as B
import Data.Time (UTCTime, DiffTime)
import Data.Attoparsec.Text
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.ByteString.Char8 as B (map)
import Data.Char (isAlphaNum)
import Blaze.ByteString.Builder
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as I

import Network.Wai.Handler.Warp

warpit :: IO ()
warpit = run 3000 app

app :: Application
app req sendResponse = case pathInfo req of
    ["foo", "bar"] -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested /foo/bar")
    ["foo", "rawquery"] -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString . rawQueryString $ req)
    ["foo", "query"] -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromString . show . W.queryString $ req)
    ["foo", "requestHeaders"] -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromString . show . W.requestHeaders $ req)
    _ -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")

{-|
  Produce the request to the authentication server as a response
-}
ucamWebAuthHello :: UTCTime -> AuthRequest a
ucamWebAuthHello time = AuthRequest {
                  requestVer = WLS3
                , requestUrl = "http://localhost/woohoo"
                , requestDesc = Just "This is a sample"
                , requestAauth = Just [Pwd]
                , requestIact = Nothing
                , requestMsg = Just "This is a private resource, or something."
                , requestParams = Nothing
                , requestDate = pure time
                , requestFail = Just "Failure to launch"
                }

{-|
  Parse the response to the authentication server as a request
-}

newtype Base64BS = B64 { unB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

data AuthRequest a = AuthRequest {
                  requestVer :: WLSVersion -- ^ The version of WLS. 1, 2 or 3.
                , requestUrl :: Text -- ^ Full http(s) url of resource request for display
                , requestDesc :: Maybe ByteString -- ^ ASCII description
                , requestAauth :: Maybe [AuthType] -- ^ Comma delimited sequence of text tokens representing satisfactory authentication methods
                , requestIact :: Maybe Bool -- ^ A token (Yes/No). Yes requires re-authentication. No required no re-authentication.
                , requestMsg :: Maybe Text -- ^ Why is authentication being requested?
                , requestParams :: Maybe a -- ^ Data to be returned to the application
                , requestDate :: Maybe UTCTime -- ^ RFC 3339 representation of application’s time
                , requestFail :: Maybe Text -- ^ Error token
                }
    deriving (Show, Eq, Ord)

data AuthResponse a = AuthResponse {
                  responseVer :: WLSVersion -- ^ The version of WLS. 1, 2 or 3, <= the request
                , responseStatus :: Status -- ^ 3 digit status code (200 is success)
                , responseMsg :: Maybe Text -- ^ The status, for users
                , responseIssue :: UTCTime -- ^ RFC 3339 representation of response’s time
                , responseId :: Text -- ^ Not unguessable identifier, id + issue are unique
                , responseUrl :: Text -- ^ Same as request
                , responsePrincipal :: Maybe Text -- ^ Identity of authenticated user. Must be present if responseStatus is 200, otherwise must be Nothing
                , responsePtags :: Maybe [Text] -- ^ Comma separated attributes of principal. Optional in version 3, must be Nothing otherwise.
                , responseAuth :: Maybe AuthType -- ^ Authentication type if successful, else Nothing
                , responseSso :: Maybe [AuthType] -- ^ Comma separated list of previous authentications. Required if responseAuth is Nothing.
                , responseLife :: Maybe DiffTime -- ^ Remaining lifetime in seconds of application
                , responseParams :: Maybe a -- ^ A copy of the params from the request
                , responseKid :: Maybe Text -- ^ RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
                , responseSig :: Maybe UcamBase64BS -- ^ Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/="
                }
    deriving (Show, Eq, Ord)

data WLSVersion = WLS1 | WLS2 | WLS3
    deriving (Read, Eq, Ord, Enum, Bounded)

instance Show WLSVersion where
    show WLS1 = "1"
    show WLS2 = "2"
    show WLS3 = "3"

parseWLSVersion :: Text -> Maybe WLSVersion
parseWLSVersion = maybeResult . parse wlsVersionParser

wlsVersionParser :: Parser WLSVersion
wlsVersionParser = choice [
                            "3" *> pure WLS3
                          , "2" *> pure WLS2
                          , "1" *> pure WLS1
                          ]

data AuthType = Pwd -- ^ pwd: Username and password
    deriving (Show, Read, Eq, Ord, Enum, Bounded)

responseCodes :: IntMap Status
responseCodes = I.fromList . fmap (statusCode &&& id) $ [ok200, gone410, noauth510, protoerr520, paramerr530, nointeract540, unauthagent560, declined570]

noauth510, protoerr520, paramerr530, nointeract540, unauthagent560, declined570 :: Status
noauth510 = mkStatus 510 "No mutually acceptable authentication types"
protoerr520 = mkStatus 520 "Unsupported protocol version (Only for version 1)"
paramerr530 = mkStatus 530 "General request parameter error"
nointeract540 = mkStatus 540 "Interaction would be required but has been blocked"
unauthagent560 = mkStatus 560 "Application agent is not authorised"
declined570 = mkStatus 570 "Authentication declined"

parseResponseCode :: Text -> Maybe Status
parseResponseCode = flip lookup responseCodes <=< maybeResult . parse decimal

newtype UcamTime = UcamTime { unUcamTime :: Text }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

convertB64Ucam :: Base64BS -> UcamBase64BS
convertB64Ucam = UcamB64 . B.map camFilter . unB64
    where
        camFilter :: Char -> Char
        camFilter '+' = '-'
        camFilter '/' = '.'
        camFilter '=' = '_'
        camFilter x = x

convertUcamB64 :: UcamBase64BS -> Base64BS
convertUcamB64 = B64 . B.map camFilter . unUcamB64
    where
        camFilter :: Char -> Char
        camFilter '-' = '+'
        camFilter '.' = '/'
        camFilter '_' = '='
        camFilter x = x

encodeB64 :: Text -> Base64BS
encodeB64 = B64 . B.encode . encodeUtf8

ucamTime :: UTCTime -> UcamTime
ucamTime = UcamTime . T.filter isAlphaNum . formatTimeRFC3339 . utcToZonedTime utc

parseUcamTime :: UcamTime -> Maybe UTCTime
parseUcamTime = fmap zonedTimeToUTC . parseTimeRFC3339 . unUcamTime <=< maybeResult . parse ucamTimeParser . unUcamTime

ucamTimeParser :: Parser UcamTime
ucamTimeParser = do
        year <- take 4
        month <- take 2
        day <- take 2 <* "T"
        hour <- take 2
        minute <- take 2
        sec <- take 2 <* "Z"
        return . UcamTime . mconcat $ [year, "-", month, "-", day, "T", hour, ":", minute, ":", sec, "Z"]

ravenAuth :: Text
ravenAuth = "https://raven.cam.ac.uk/authenticate.html"
