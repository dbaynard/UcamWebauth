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

import Import.NoFoundation hiding (take, catMaybes)
import Control.Applicative (empty, Alternative)
import Control.Error
import Network.HTTP.Types ()
import Network.Wai
import qualified Network.Wai as W
import Data.Time.RFC3339
import Data.Time.LocalTime
import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Base64.Lazy as L
import Data.Time (DiffTime, secondsToDiffTime, NominalDiffTime, diffUTCTime)
import Data.Attoparsec.ByteString.Char8 hiding (count)
import qualified Data.Attoparsec.ByteString.Char8 as A
import Data.Attoparsec.Combinator (lookAhead)
import qualified Data.Text as T
import qualified Data.ByteString.Char8 as B
import Data.Char (isAlphaNum)
import Blaze.ByteString.Builder hiding (Builder)
import qualified Blaze.ByteString.Builder as Z
import qualified Blaze.ByteString.Builder.Char.Utf8 as Z
import Data.IntMap.Strict ()
import qualified Data.IntMap.Strict as I
import Data.Map.Strict ()
import qualified Data.Map.Strict as M
import Data.Aeson ()
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy as LB (ByteString)

import Crypto.PubKey.RSA.Types
import Crypto.PubKey.RSA.PKCS15
import Crypto.Hash.Algorithms
import Data.X509
import System.IO (withFile, IOMode(..))
import Data.PEM

import Network.Wai.Handler.Warp

type LBS = LB.ByteString
type StringType = ByteString

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
        =<< displayWLSResponse req 
    ["foo", "queryR"] -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (displayWLSQuery req)
    ["foo", "requestHeaders"] -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (Z.fromShow . W.requestHeaders $ req)
    ["foo", "authenticate"] -> response $ responseBuilder
        seeOther303
        [("Content-Type", "text/plain"), ucamWebauthQuery ravenAuth . ucamWebauthHello (Just "This is 100% of the data! And it’s really quite cool" :: Maybe Text) $ time]
        mempty
    _ -> response $ responseBuilder
        status200
        [("Content-Type", "text/plain")]
        (fromByteString "You requested something else")

displayWLSQuery :: W.Request -> Z.Builder
displayWLSQuery = maybe mempty Z.fromShow . lookUpWLSResponse

displayWLSResponse :: W.Request -> IO Z.Builder
displayWLSResponse = displayAuthResponse <=< liftMaybe . lookUpWLSResponse

displayAuthResponse :: ByteString -> IO Z.Builder
displayAuthResponse = maybeT empty (pure . Z.fromShow) . maybeAuthCode

maybeAuthCode :: (MonadIO m, MonadPlus m) => ByteString -> m (SignedAuthResponse Text)
maybeAuthCode = validateAuthResponse <=< liftMaybe . maybeResult . flip feed "" . parse ucamResponseParser

lookUpWLSResponse :: W.Request -> Maybe ByteString
lookUpWLSResponse = join . M.lookup "WLS-Response" . M.fromList . W.queryString

{-|
  Produce the request to the authentication server as a response
-}
ucamWebauthHello :: ToJSON a => Maybe a -> UTCTime -> AuthRequest a
ucamWebauthHello params time = AuthRequest {
                  ucamQVer = WLS3
                , ucamQUrl = "http://localhost:3000/foo/query"
                , ucamQDesc = Just "This is a sample; it’s rather excellent!"
                , ucamQAauth = Nothing
                , ucamQIact = Nothing
                , ucamQMsg = Just "This is a private resource, or something."
                , ucamQParams = params
                , ucamQDate = pure time
                , ucamQFail = pure False
                }

ucamWebauthQuery :: ToJSON a => Z.Builder -> AuthRequest a -> Header
ucamWebauthQuery url AuthRequest{..} = (hLocation, toByteString $ url <> theQuery)
    where
        theQuery :: Z.Builder
        theQuery = renderQueryBuilder True $ strictQs <> textQs <> lazyQs
        strictQs :: Query
        strictQs = toQuery [
                   ("ver", pure . textWLSVersion $ ucamQVer) :: (Text, Maybe ByteString)
                 , ("desc", encodeUtf8 <$> ucamQDesc)
                 , ("iact", boolToYNS <$> ucamQIact)
                 , ("fail", boolToYNS <$> ucamQFail)
                 ]
        textQs :: Query
        textQs = toQuery [
                   ("url" , pure ucamQUrl) :: (Text, Maybe Text)
                 , ("date", unUcamTime . ucamTime <$> ucamQDate)
                 , ("aauth", T.intercalate "," . fmap displayAuthType <$> ucamQAauth)
                 , ("msg", ucamQMsg)
                 ]
        lazyQs :: Query
        lazyQs = toQuery [
                   ("params", L.encode . A.encode <$> ucamQParams) :: (Text, Maybe LBS)
                 ]

{-|
  Parse the response to the authentication server as a request
-}
ucamResponseParser :: forall a . FromJSON a => Parser (SignedAuthResponse a)
ucamResponseParser = do
        (ucamAToSign, ucamAResponse@AuthResponse{..}) <- noBang . match $ ucamAuthResponseParser
        (ucamAKid, ucamASig) <- parseKidSig ucamAStatus
        endOfInput
        return SignedAuthResponse{..}
        where
            ucamAuthResponseParser :: Parser (AuthResponse a)
            ucamAuthResponseParser = do
                    ucamAVer <- noBang wlsVersionParser
                    ucamAStatus <- noBang responseCodeParser
                    ucamAMsg <- maybeBang . urlWrapText $ betweenBangs
                    ucamAIssue <- noBang $ fromMaybe ancientUTCTime <$> utcTimeParser
                    ucamAId <- noBang . urlWrapText $ betweenBangs
                    ucamAUrl <- noBang . urlWrapText $ betweenBangs
                    ucamAPrincipal <- parsePrincipal ucamAStatus
                    ucamAPtags <- parsePtags ucamAVer
                    ucamAAuth <- noBang . optionMaybe $ authTypeParser
                    ucamASso <- parseSso ucamAStatus ucamAAuth
                    ucamALife <- noBang . optionMaybe . fmap secondsToDiffTime $ decimal
                    ucamAParams <- A.decodeStrict . B.decodeLenient <$> betweenBangs
                    return AuthResponse{..}
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
            parsePrincipal :: Status -> Parser (Maybe Text)
            parsePrincipal (statusCode -> 200) = maybeBang . urlWrapText $ betweenBangs
            parsePrincipal _ = noBang . pure $ empty
            parseSso :: Status -> Maybe AuthType -> Parser (Maybe [AuthType])
            parseSso (statusCode -> 200) Nothing = noBang . fmap pure $ authTypeParser `sepBy1` ","
            parseSso _ _ = noBang . pure $ empty
            parseKidSig :: Status -> Parser (Maybe StringType, Maybe UcamBase64BS)
            parseKidSig (statusCode -> 200) = curry (pure *** pure)
                                       <$> noBang kidParser
                                       <*> ucamB64parser
            parseKidSig _ = (,) <$> noBang (optionMaybe kidParser) <*> optionMaybe ucamB64parser

betweenBangs :: Parser StringType
betweenBangs = takeWhile1 (/= '!')

kidParser :: Parser StringType
kidParser = fmap B.pack $ (:)
        <$> (satisfy . inClass $ "1-9")
        <*> (fmap catMaybes . A.count 7 . optionMaybe $ digit) <* (lookAhead . satisfy $ not . isDigit)

{-|
  Validate the Authentication Response
-}
validateAuthResponse :: (MonadIO m, MonadPlus m) => SignedAuthResponse a -> m (SignedAuthResponse a)
validateAuthResponse x@SignedAuthResponse{..} = do
        guard . validateKid =<< liftMaybe ucamAKid
        guard <=< validateSig $ x
        guard <=< validateIssueTime $ ucamAResponse
        return x

{-|
  Check the kid is valid
-}
validateKid :: StringType -> Bool
validateKid = flip elem ["2"]

{-|
  Validate the signature
-}

validateSig :: (MonadPlus m, MonadIO m) => SignedAuthResponse a -> m Bool
validateSig = validateSigKey getKey 

decodePubKey :: ByteString -> Maybe PublicKey
decodePubKey = hush . f
    where
        f :: ByteString -> Either String PublicKey
        f = getRSAKey . certPubKey . getCertificate <=< decodeSignedCertificate . pemContent <=< headErr "Empty list" <=< pemParseBS

getKey :: (MonadIO m, Alternative m) => StringType -> m PublicKey
getKey key = liftMaybe <=< liftIO . withFile ("pubkey" <> B.unpack key <> ".crt") ReadMode $ 
        pure . decodePubKey <=< B.hGetContents

validateSigKey :: forall m a . MonadPlus m => (StringType -> m PublicKey) -> SignedAuthResponse a -> m Bool
validateSigKey importKey SignedAuthResponse{..} = pure . rsaValidate =<< importKey =<< liftMaybe ucamAKid
    where
        rsaValidate :: PublicKey -> Bool
        rsaValidate key = verify (Just SHA1) key message signature
        message :: ByteString
        message = ucamAToSign
        signature :: ByteString
        signature = maybe mempty decodeUcamB64 ucamASig

{-|
  Validate the time of issue
-}

allowedSyncTime :: NominalDiffTime
allowedSyncTime = 40

validateIssueTime :: (MonadIO m) => AuthResponse a -> m Bool
validateIssueTime AuthResponse{..} = (>) allowedSyncTime . flip diffUTCTime ucamAIssue <$> liftIO getCurrentTime

newtype ASCII = ASCII { unASCII :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

newtype Base64BS = B64 { unB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString)

data AuthRequest a = AuthRequest {
                  ucamQVer :: WLSVersion -- ^ The version of WLS. 1, 2 or 3.
                , ucamQUrl :: Text -- ^ Full http(s) url of resource request for display
                , ucamQDesc :: Maybe Text -- ^ Description, transmitted as ASCII
                , ucamQAauth :: Maybe [AuthType] -- ^ Comma delimited sequence of text tokens representing satisfactory authentication methods
                , ucamQIact :: Maybe Bool -- ^ A token (Yes/No). Yes requires re-authentication. No required no re-authentication.
                , ucamQMsg :: Maybe Text -- ^ Why is authentication being requested?
                , ucamQParams :: Maybe a -- ^ Data to be returned to the application
                , ucamQDate :: Maybe UTCTime -- ^ RFC 3339 representation of application’s time
                , ucamQFail :: Maybe Bool -- ^ Error token. If 'yes', the WLS implements error handling
                }
    deriving (Show, Eq, Ord)

data SignedAuthResponse a = SignedAuthResponse {
                  ucamAResponse :: AuthResponse a -- ^ The bit of the response that is signed
                , ucamAToSign :: ByteString
                , ucamAKid :: Maybe ByteString -- ^ RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
                , ucamASig :: Maybe UcamBase64BS -- ^ Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/="
                }
    deriving (Show, Eq, Ord)

data AuthResponse a = AuthResponse {
                  ucamAVer :: WLSVersion -- ^ The version of WLS. 1, 2 or 3, <= the request
                , ucamAStatus :: Status -- ^ 3 digit status code (200 is success)
                , ucamAMsg :: Maybe Text -- ^ The status, for users
                , ucamAIssue :: UTCTime -- ^ RFC 3339 representation of response’s time
                , ucamAId :: Text -- ^ Not unguessable identifier, id + issue are unique
                , ucamAUrl :: Text -- ^ Same as request
                , ucamAPrincipal :: Maybe Text -- ^ Identity of authenticated user. Must be present if ucamAStatus is 200, otherwise must be Nothing
                , ucamAPtags :: Maybe [Text] -- ^ Comma separated attributes of principal. Optional in version 3, must be Nothing otherwise.
                , ucamAAuth :: Maybe AuthType -- ^ Authentication type if successful, else Nothing
                , ucamASso :: Maybe [AuthType] -- ^ Comma separated list of previous authentications. Required if ucamAAuth is Nothing.
                , ucamALife :: Maybe DiffTime -- ^ Remaining lifetime in seconds of application
                , ucamAParams :: Maybe a -- ^ A copy of the params from the request
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
boolToYN True = "yes"
boolToYN _ = "no"

boolToYNS :: Bool -> StringType
boolToYNS = boolToYN

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

decodeUcamB64 :: UcamBase64BS -> StringType
decodeUcamB64 = B.decodeLenient . unB64 . convertUcamB64

encodeUcamB64 :: StringType -> UcamBase64BS
encodeUcamB64 = convertB64Ucam . B64 . B.encode

ucamB64parser :: Parser UcamBase64BS
ucamB64parser = UcamB64 <$> takeWhile1 (ors [isAlphaNum, inClass "-._"])

decodeASCII :: ASCII -> Text
decodeASCII = decodeUtf8 . B.filter isAlpha_ascii . unASCII

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

liftMaybe :: Alternative f => Maybe a -> f a
liftMaybe = maybe empty pure

getRSAKey :: Alternative f => PubKey -> f PublicKey
getRSAKey (PubKeyRSA x) = pure x
getRSAKey _ = empty
