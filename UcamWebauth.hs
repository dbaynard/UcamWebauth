{-|
Module      : Ucam-Webauth
Description : Authenticate using the Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

This module implements the University of Cambridge’s Ucam-Webauth protocol,
as in the link below. The protocol is a handshake between the

  [@WAA@] application wishing to authenticate (whatever uses this module!), and
  [@WLS@] server which can authenticate the user, and return relevant information

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

See the "RavenAuth" module for a specific implementation.

-}

module UcamWebauth (
    module UcamWebauth
)   where

-- Prelude
import ClassyPrelude hiding (take, catMaybes)
import Data.Data
import GHC.Generics
import Data.Coerce

import Control.Applicative (empty, Alternative)
import Control.Error

import System.IO (withFile, IOMode(..))

-- Wai and http protocol
import Network.Wai
import Network.HTTP.Types

-- Time
import Data.Time.RFC3339
import Data.Time.LocalTime
import Data.Time (DiffTime, secondsToDiffTime, NominalDiffTime, diffUTCTime)

-- Character encoding
import Data.Char (isAlphaNum)

import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Base64.Lazy as L

import qualified Data.Text as T

import qualified Data.ByteString.Char8 as B

-- ByteString building
import Blaze.ByteString.Builder hiding (Builder)
import qualified Blaze.ByteString.Builder as Z (Builder)

-- Parsing
import Data.Attoparsec.Combinator (lookAhead)
import Data.Attoparsec.ByteString.Char8 hiding (count)
import qualified Data.Attoparsec.ByteString.Char8 as A

-- Map structures
import Data.IntMap.Strict ()
import qualified Data.IntMap.Strict as I
import Data.Map.Strict ()
import qualified Data.Map.Strict as M

-- JSON (Aeson)
import Data.Aeson (ToJSON, FromJSON)
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy as LB (ByteString)

-- Crypto
import Crypto.PubKey.RSA.Types
import Crypto.PubKey.RSA.PKCS15
import Crypto.Hash.Algorithms
import Data.X509
import Data.PEM

------------------------------------------------------------------------------
-- * Core data types and associated functions

------------------------------------------------------------------------------
-- ** Return type

{-|
  'UcamWebauthInfo' is returned from this module. The parameter 'a' represents data sent
  in the initial connection, that must be returned. The constructor and accessors are *not*
  exported from the module, to present an abstract API.
-}
data UcamWebauthInfo a = AuthInfo {
                  approveUniq :: (UTCTime, Text) -- ^ Unique representation of response, composed of issue and id
                , approveUser :: Text -- ^ Identity of authenticated user
                , approveAttribs :: [Ptag] -- ^ Comma separated attributes of user
                , approveLife :: Maybe DiffTime -- ^ Remaining lifetime in seconds of application
                , approveParams :: Maybe a -- ^ A copy of the params from the request
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

------------------------------------------------------------------------------
-- ** Type Synonyms

{-|
  Shorter type synonym for lazy ByteString, and a synonym to abstract much behaviour over a generic string type.
-}
type LBS = LB.ByteString
type StringType = ByteString

deriving instance Data Status

------------------------------------------------------------------------------
-- ** 'ByteString' newtypes

{-|
  Ensure ASCII text is not confused with other ByteStrings
-}
newtype ASCII = ASCII { unASCII :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Ensure Base 64 text is not confused with other ByteStrings
-}
newtype Base64BS = B64 { unB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Ensure Base 64 text modified to fit the Ucam-Webauth protocol is not confused with other ByteStrings
-}
newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

------------------------------------------------------------------------------
-- ** Request and response
{- $request
  The handshake between the @WLS@ and @WAA@ are represented using the 'AuthRequest'
  and 'SignedAuthResponse' data types. The 'AuthResponse' type represents the
  content of a 'SignedAuthResponse'. Constructors and accessors are not exported,
  and the 'AuthRequest' should be build using the smart constructors provided.
-}

{-|
  An 'AuthRequest' is constructed by the @WAA@, using the constructor functions
  of this module. The parameter represents data to be returned to the application
  after authentication.
-}
data AuthRequest a = AuthRequest {
                  ucamQVer :: WLSVersion -- ^ The version of @WLS.@ 1, 2 or 3.
                , ucamQUrl :: Text -- ^ Full http(s) url of resource request for display
                , ucamQDesc :: Maybe Text -- ^ Description, transmitted as ASCII
                , ucamQAauth :: Maybe [AuthType] -- ^ Comma delimited sequence of text tokens representing satisfactory authentication methods
                , ucamQIact :: Maybe Bool -- ^ A token (Yes/No). Yes requires re-authentication. No requires no interaction.
                , ucamQMsg :: Maybe Text -- ^ Why is authentication being requested?
                , ucamQParams :: Maybe a -- ^ Data to be returned to the application
                , ucamQDate :: Maybe UTCTime -- ^ RFC 3339 representation of application’s time
                , ucamQFail :: Maybe Bool -- ^ Error token. If 'yes', the @WLS@ implements error handling
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  A 'SignedAuthResponse' represents the data returned by the @WLS@, including a
  representation of the content returned (in the 'AuthResponse' data type), and
  the cryptographic signature, for verification.

  The phantom parameter 'valid' corr
-}
data SignedAuthResponse (valid :: IsValid) a = SignedAuthResponse {
                  ucamAResponse :: AuthResponse a -- ^ The bit of the response that is signed
                , ucamAToSign :: ByteString -- ^ The raw text of the response, used to verify the signature
                , ucamAKid :: Maybe ByteString -- ^ RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
                , ucamASig :: Maybe UcamBase64BS -- ^ Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/="
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  The intended use of this is with 'IsValid' as a kind (requires the 'DataKinds' extension).
  The data constructors 'Valid' and 'MaybeValid' are now type constructors, which indicate the
  validity of a 'SignedAuthResponse'.

  TODO This is not exported.
-}
data IsValid = MaybeValid
             | Valid
             deriving (Show, Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

{-|
  An 'AuthResponse' represents the content returned by the @WLS@. The validation
  machinery in this module returns the required data as a 'UcamWebauthInfo' value.
-}
data AuthResponse a = AuthResponse {
                  ucamAVer :: WLSVersion -- ^ The version of @WLS@: 1, 2 or 3
                , ucamAStatus :: Status -- ^ 3 digit status code (200 is success)
                , ucamAMsg :: Maybe Text -- ^ The status, for users
                , ucamAIssue :: UTCTime -- ^ RFC 3339 representation of response’s time
                , ucamAId :: Text -- ^ Not unguessable identifier, id + issue are unique
                , ucamAUrl :: Text -- ^ Same as request
                , ucamAPrincipal :: Maybe Text -- ^ Identity of authenticated user. Must be present if ucamAStatus is 200, otherwise must be Nothing
                , ucamAPtags :: Maybe [Ptag] -- ^ Comma separated attributes of principal. Optional in version 3, must be Nothing otherwise.
                , ucamAAuth :: Maybe AuthType -- ^ Authentication type if successful, else Nothing
                , ucamASso :: Maybe [AuthType] -- ^ Comma separated list of previous authentications. Required if ucamAAuth is Nothing.
                , ucamALife :: Maybe DiffTime -- ^ Remaining lifetime in seconds of application
                , ucamAParams :: Maybe a -- ^ A copy of the params from the request
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  Takes a validated 'SignedAuthResponse', and returns the corresponding 'UcamWebauthInfo'.
-}
getAuthInfo :: Alternative f => SignedAuthResponse 'Valid a -> f (UcamWebauthInfo a)
getAuthInfo = extractAuthInfo . ucamAResponse

{-|
  Convert an 'AuthResponse' into a 'UcamWebauthInfo' for export.

  TODO This should not be exported. Instead export 'getAuthInfo'
-}
extractAuthInfo :: Alternative f => AuthResponse a -> f (UcamWebauthInfo a)
extractAuthInfo AuthResponse{..} = liftMaybe $ do
        approveUser <- ucamAPrincipal
        return AuthInfo{..}
        where
            approveUniq = (ucamAIssue, ucamAId)
            approveAttribs = fromMaybe empty ucamAPtags
            approveLife = ucamALife
            approveParams = ucamAParams

------------------------------------------------------------------------------
-- * 

{-|
  'maybeAuthInfo' takes the 'AuthRequest' from its environment, and a 'ByteString' containing the @WLS@
  response, and if the response is valid, returns a 'UcamWebauthInfo' value.

  TODO When the errors returned can be usefully used, ensure this correctly returns a lifted
  'Either b (UcanWebauthInfo a)' response.
-}
maybeAuthInfo :: (MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m, a ~ Text) => ByteString -> m (UcamWebauthInfo a)
maybeAuthInfo = getAuthInfo <=< maybeAuthCode

{-|
  A helper function to parse and validate a response from a @WLS@.
-}
maybeAuthCode :: (MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m, a ~ Text) => ByteString -> m (SignedAuthResponse 'Valid a)
maybeAuthCode = validateAuthResponse <=< liftMaybe . maybeResult . flip feed "" . parse ucamResponseParser

lookUpWLSResponse :: Request -> Maybe ByteString
lookUpWLSResponse = join . M.lookup "WLS-Response" . M.fromList . queryString

{-|
  Accepted authentication types, by the implementation.
-}
authAccepted :: Maybe [AuthType]
authAccepted = pure [Pwd]

needReauthentication :: Maybe Bool
needReauthentication = Nothing

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
ucamResponseParser :: forall a . FromJSON a => Parser (SignedAuthResponse 'MaybeValid a)
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
            parsePtags :: WLSVersion -> Parser (Maybe [Ptag])
            parsePtags WLS3 = noBang . optionMaybe $ ptagParser `sepBy` ","
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

  1. Validate the key id
  2. Validate the cryptographic signature against the relevant key
  3. Validate the issue time
  4. Validate the url is the same as that transmitted
  5. Validate the auth and sso values are valid
-}
validateAuthResponse :: forall a m . (MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m) => SignedAuthResponse 'MaybeValid a -> m (SignedAuthResponse 'Valid a)
validateAuthResponse x@SignedAuthResponse{..} = do
        guard . validateKid =<< liftMaybe ucamAKid
        guard <=< validateSig $ x
        guard <=< validateIssueTime $ ucamAResponse
        guard <=< validateUrl $ ucamAResponse
        guard <=< validateAuthTypes $ ucamAResponse
        return . makeValid $ x
        where
            makeValid :: SignedAuthResponse 'MaybeValid a -> SignedAuthResponse 'Valid a
            makeValid = coerce

{-|
  Check the kid is valid
-}
validateKid :: StringType -> Bool
validateKid = flip elem ["2"]

{-|
  Validate the signature
-}

validateSig :: (MonadPlus m, MonadIO m) => SignedAuthResponse 'MaybeValid a -> m Bool
validateSig = validateSigKey getKey 

decodePubKey :: ByteString -> Maybe PublicKey
decodePubKey = hush . f
    where
        f :: ByteString -> Either String PublicKey
        f = getRSAKey . certPubKey . getCertificate <=< decodeSignedCertificate . pemContent <=< headErr "Empty list" <=< pemParseBS

getKey :: (MonadIO m, Alternative m) => StringType -> m PublicKey
getKey key = liftMaybe <=< liftIO . withFile ("pubkey" <> B.unpack key <> ".crt") ReadMode $ 
        pure . decodePubKey <=< B.hGetContents

validateSigKey :: forall m a . MonadPlus m => (StringType -> m PublicKey) -> SignedAuthResponse 'MaybeValid a -> m Bool
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

{-|
  Check the url parameter matches that sent
-}
validateUrl :: (MonadReader (AuthRequest a) m) => AuthResponse a -> m Bool
validateUrl AuthResponse{..} = (==) ucamAUrl . ucamQUrl <$> ask

{-|
  Check the authentication type matches that sent.

  If the iact variable is Yes, only return 'True' if the aauth value is acceptable.
  If the iact variable is No, only return 'True' if sso contains a value that is acceptable.
  If the iact variable is unset, return 'True' if there is an acceptable value in either field.

-}

validateAuthTypes :: forall a f . (Alternative f) => AuthResponse a -> f Bool
validateAuthTypes AuthResponse{..} = maybe validateAnyAuth validateSpecificAuth needReauthentication
    where
        isAcceptableAuth :: AuthType -> Bool
        isAcceptableAuth = flip elem (fromMaybe defaultAuthAccepted authAccepted)
        anyAuth :: Maybe AuthType -> Maybe [AuthType] -> Bool
        anyAuth Nothing (Just x) = any isAcceptableAuth x
        anyAuth (Just x) Nothing = isAcceptableAuth x
        anyAuth _ _ = False
        validateAnyAuth :: f Bool
        validateAnyAuth = pure $ anyAuth ucamAAuth ucamASso
        validateSpecificAuth :: Bool -> f Bool
        validateSpecificAuth True = isAcceptableAuth <$> liftMaybe ucamAAuth
        validateSpecificAuth _ = any isAcceptableAuth <$> liftMaybe ucamASso


data WLSVersion = WLS1 | WLS2 | WLS3
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

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
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

defaultAuthAccepted :: [AuthType]
defaultAuthAccepted = [Pwd]

displayAuthType :: IsString a => AuthType -> a
displayAuthType Pwd = "pwd"

instance Show AuthType where
    show = displayAuthType

parseAuthType :: StringType -> Maybe AuthType
parseAuthType = maybeResult . parse authTypeParser

authTypeParser :: Parser AuthType
authTypeParser = "pwd" *> pure Pwd

data Ptag = Current -- ^ User is current member of university
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

displayPtag :: IsString a => Ptag -> a
displayPtag Current = "current"

instance Show Ptag where
    show = displayPtag

parsePtag :: StringType -> Maybe Ptag
parsePtag = maybeResult . parse ptagParser

ptagParser :: Parser Ptag
ptagParser = "current" *> pure Current

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
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

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
