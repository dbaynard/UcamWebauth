{-|
Module      : Ucam-Webauth
Description : Authenticate with the University of Cambridge protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

https://raven.cam.ac.uk/project/waa2wls-protocol.txt

-}

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}

module UcamWebauth (
    module UcamWebauth
)   where

import Import.NoFoundation hiding (take)
import Control.Applicative (empty)
import Network.HTTP.Types
import Network.Wai
import qualified Network.Wai as W
import Network.Wai.Parse
import Data.Time.RFC3339
import Data.Time.LocalTime
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Base64.Lazy as L
import Data.Time (UTCTime, DiffTime, secondsToDiffTime)
import Data.Attoparsec.ByteString.Char8 hiding (count)
import qualified Data.Attoparsec.ByteString.Char8 as A
import Data.Attoparsec.Combinator (lookAhead)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString.Char8 as B
import Data.Char (isAlphaNum)
import Blaze.ByteString.Builder hiding (Builder)
import qualified Blaze.ByteString.Builder as Z
import qualified Blaze.ByteString.Builder.Char.Utf8 as Z
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as I
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.Aeson (ToJSON, FromJSON)
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy as LB (ByteString)

import Network.Wai.Handler.Warp

type LBS = LB.ByteString
type StringType = ByteString

warpit :: IO ()
warpit = run 3000 . app =<< getCurrentTime

app :: UTCTime -> Application
app time req sendResponse = case pathInfo req of
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
        (displayWLSResponse req)
    ["foo", "queryR"] -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (displayWLSQuery req)
    ["foo", "requestHeaders"] -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (Z.fromShow . W.requestHeaders $ req)
    ["foo", "authenticate"] -> sendResponse $ responseBuilder
        seeOther303
        [("Content-Type", "text/plain"), ucamWebauthQuery ravenAuth . ucamWebauthHello (Just "This is 100% of the data! And it’s really quite cool" :: Maybe Text) $ time]
        mempty
    _ -> sendResponse $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")

displayWLSQuery :: W.Request -> Z.Builder
displayWLSQuery = maybe mempty Z.fromShow . lookUpWLSResponse

displayWLSResponse :: W.Request -> Z.Builder
displayWLSResponse = maybe mempty Z.fromShow . maybeAuthCode
    where
        maybeAuthCode :: W.Request -> Maybe (AuthResponse Text)
        maybeAuthCode = maybeResult . parse ucamResponseParser <=< lookUpWLSResponse

lookUpWLSResponse :: W.Request -> Maybe ByteString
lookUpWLSResponse = join . M.lookup "WLS-Response" . M.fromList . W.queryString

{-|
  Produce the request to the authentication server as a response
-}
ucamWebauthHello :: ToJSON a => Maybe a -> UTCTime -> AuthRequest a
ucamWebauthHello params time = AuthRequest {
                  requestVer = WLS3
                , requestUrl = "http://localhost:3000/foo/query"
                , requestDesc = Just "This is a sample; it’s rather excellent!"
                , requestAauth = Nothing
                , requestIact = Nothing
                , requestMsg = Just "This is a private resource, or something."
                , requestParams = params
                , requestDate = pure time
                , requestFail = Just "Failure to launch"
                }

ucamWebauthQuery :: ToJSON a => Z.Builder -> AuthRequest a -> Header
ucamWebauthQuery url AuthRequest{..} = (hLocation, toByteString $ url <> theQuery)
    where
        theQuery :: Z.Builder
        theQuery = renderQueryBuilder True $ strictQs <> textQs <> lazyQs
        strictQs :: Query
        strictQs = toQuery [
                   ("ver", pure . textWLSVersion $ requestVer) :: (Text, Maybe ByteString)
                 , ("desc", encodeUtf8 <$> requestDesc)
                 ]
        textQs :: Query
        textQs = toQuery [
                   ("url" , pure requestUrl) :: (Text, Maybe Text)
                 , ("date", unUcamTime . ucamTime <$> requestDate)
                 , ("aauth", T.intercalate "," . fmap displayAuthType <$> requestAauth)
                 , ("iact", boolToYN <$> requestIact)
                 , ("msg", requestMsg)
                 , ("fail", requestFail)
                 ]
        lazyQs :: Query
        lazyQs = toQuery [
                   ("params", L.encode . A.encode <$> requestParams) :: (Text, Maybe LBS)
                 ]

{-|
  Parse the response to the authentication server as a request
-}
ucamResponseParser :: FromJSON a => Parser (AuthResponse a)
ucamResponseParser = do
        responseVer <- noBang wlsVersionParser
        responseStatus <- noBang responseCodeParser
        responseMsg <- maybeBang . urlWrapText $ betweenBangs
        responseIssue <- noBang $ fromMaybe ancientUTCTime <$> utcTimeParser
        responseId <- noBang . urlWrapText $ betweenBangs
        responseUrl <- noBang . urlWrapText $ betweenBangs
        responsePrincipal <- maybeBang . urlWrapText $ betweenBangs
        responsePtags <- parsePtags responseVer
        responseAuth <- noBang . optionMaybe $ authTypeParser
        responseSso <- noBang . optionMaybe $ authTypeParser `sepBy1` ","
        responseLife <- noBang . optionMaybe . fmap secondsToDiffTime $ decimal
        responseParams <- A.decodeStrict . B.decodeLenient <$> noBang betweenBangs
        responseKid <- maybeBang . urlWrap $ kidParser
        responseSig <- optionMaybe ucamB64parser
        return AuthResponse{..}
        where
            noBang :: Parser b -> Parser b
            noBang = (<* "!")
            urlWrap :: Functor f => f StringType -> f ByteString
            urlWrap = fmap (urlDecode False)
            urlWrapText :: Functor f => f StringType -> f Text
            urlWrapText = fmap (decodeUtf8 . urlDecode False)
            maybeBang :: Parser b -> Parser (Maybe b)
            maybeBang = noBang . optionMaybe
            parsePtags :: WLSVersion -> Parser (Maybe [Text])
            parsePtags WLS3 = noBang . optionMaybe . fmap urlWrapText . many1 $ (takeWhile1 . nots $ ",!") <* optionMaybe ","
            parsePtags _ = pure empty

betweenBangs :: Parser StringType
betweenBangs = takeWhile1 (/= '!')

kidParser :: Parser StringType
kidParser = fmap B.pack $ (:)
        <$> (satisfy . inClass $ "1-9")
        <*> (fmap catMaybes . A.count 7 . optionMaybe $ digit) <* (lookAhead . satisfy $ not . isDigit)

newtype ASCII = ASCII { unASCII :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

newtype Base64BS = B64 { unB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

data AuthRequest a = AuthRequest {
                  requestVer :: WLSVersion -- ^ The version of WLS. 1, 2 or 3.
                , requestUrl :: Text -- ^ Full http(s) url of resource request for display
                , requestDesc :: Maybe Text -- ^ Description, transmitted as ASCII
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
                , responseKid :: Maybe ByteString -- ^ RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
                , responseSig :: Maybe UcamBase64BS -- ^ Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/="
                }
    deriving (Show, Eq, Ord)

data WLSVersion = WLS1 | WLS2 | WLS3
    deriving (Read, Eq, Ord, Enum, Bounded)

displayWLSVersion :: IsString a => WLSVersion -> a
displayWLSVersion WLS1 = "1"
displayWLSVersion WLS2 = "2"
displayWLSVersion WLS3 = "3"

textWLSVersion :: WLSVersion -> StringType
textWLSVersion = displayWLSVersion

instance Show WLSVersion where
    show = displayWLSVersion

parseWLSVersion :: StringType -> Maybe WLSVersion
parseWLSVersion = maybeResult . parse wlsVersionParser

wlsVersionParser :: Parser WLSVersion
wlsVersionParser = choice [
                            "3" *> pure WLS3
                          , "2" *> pure WLS2
                          , "1" *> pure WLS1
                          ]

boolToYN :: IsString a => Bool -> a
boolToYN True = "Yes"
boolToYN _ = "No"

trueOrFalse :: StringType -> Maybe Bool
trueOrFalse = maybeResult . parse ynToBool
    where
        ynToBool :: Parser Bool
        ynToBool = ("Y" <|> "y") *> "es" *> pure True
             <|> ("N" <|> "n") *> "o" *> pure False

data AuthType = Pwd -- ^ pwd: Username and password
    deriving (Read, Eq, Ord, Enum, Bounded)

displayAuthType :: IsString a => AuthType -> a
displayAuthType Pwd = "pwd"

instance Show AuthType where
    show = displayAuthType

parseAuthType :: StringType -> Maybe AuthType
parseAuthType = maybeResult . parse authTypeParser

authTypeParser :: Parser AuthType
authTypeParser = "pwd" *> pure Pwd

responseCodes :: IntMap Status
responseCodes = I.fromList . fmap (statusCode &&& id) $ [ok200, gone410, noAuth510, protoErr520, paramErr530, noInteract540, unAuthAgent560, declined570]

noAuth510, protoErr520, paramErr530, noInteract540, unAuthAgent560, declined570 :: Status
noAuth510 = mkStatus 510 "No mutually acceptable authentication types"
protoErr520 = mkStatus 520 "Unsupported protocol version (Only for version 1)"
paramErr530 = mkStatus 530 "General request parameter error"
noInteract540 = mkStatus 540 "Interaction would be required but has been blocked"
unAuthAgent560 = mkStatus 560 "Application agent is not authorised"
declined570 = mkStatus 570 "Authentication declined"

parseResponseCode :: StringType -> Maybe Status
parseResponseCode = maybeResult . parse responseCodeParser

responseCodeParser :: Parser Status
responseCodeParser = fromMaybe badRequest400 . flip lookup responseCodes <$> decimal

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

encodeUcamB64 :: StringType -> UcamBase64BS
encodeUcamB64 = UcamB64 . B.encode

ucamB64parser :: Parser UcamBase64BS
ucamB64parser = encodeUcamB64 <$> takeWhile1 (ors [isAlphaNum, inClass ".-_"])

decodeASCII :: ASCII -> Text
decodeASCII = T.decodeASCII . unASCII

ucamTime :: UTCTime -> UcamTime
ucamTime = UcamTime . T.filter isAlphaNum . formatTimeRFC3339 . utcToZonedTime utc

parseUcamTime :: UcamTime -> Maybe UTCTime
parseUcamTime = join . maybeResult . parse utcTimeParser . encodeUtf8 . unUcamTime

utcTimeParser :: Parser (Maybe UTCTime)
utcTimeParser = fmap zonedTimeToUTC . parseTimeRFC3339 . unUcamTime <$> ucamTimeParser

ucamTimeParser :: Parser UcamTime
ucamTimeParser = do
        year <- take 4
        month <- take 2
        day <- take 2 <* "T"
        hour <- take 2
        minute <- take 2
        sec <- take 2 <* "Z"
        return . UcamTime . decodeUtf8 . mconcat $ [year, "-", month, "-", day, "T", hour, ":", minute, ":", sec, "Z"]

ravenAuth :: Z.Builder
ravenAuth = "https://raven.cam.ac.uk/auth/authenticate.html"

optionMaybe :: Parser a -> Parser (Maybe a)
optionMaybe = option empty . fmap pure

ands :: (Applicative f, Traversable t, MonoFoldable (t a), Element (t a) ~ Bool)
    => t (f a) -> f Bool
ands = fmap and . sequenceA

ors :: (Applicative f, Traversable t, MonoFoldable (t a), Element (t a) ~ Bool)
    => t (f a) -> f Bool
ors = fmap or . sequenceA

nots :: String -> Char -> Bool
nots = ands . fmap (/=)

oneOf :: (Eq a, Traversable t, MonoFoldable (t Bool), Element (t Bool) ~ Bool)
    => t a -> a -> Bool
oneOf = ors . fmap (==)

ancientUTCTime :: UTCTime
ancientUTCTime = UTCTime (ModifiedJulianDay 0) 0
