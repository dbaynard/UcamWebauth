{-|
Module      : Network.Wai.Protocol.UcamWebauth
Description : Authenticate using the Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

This module implements the client form of the University of Cambridge’s Ucam-Webauth protocol,
as in the link below. The protocol is a handshake between the

  [@WAA@], /i.e./ application wishing to authenticate (whatever uses this module!), and the
  [@WLS@], /i.e./ server which can authenticate the user

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

See the "Network.Wai.Protocol.Raven.Auth" module for a specific implementation, and
"Network.Wai.Protocol.Raven.Example" for an example.

It is necessary to store the relevant public keys, as described in the documentation
for 'readRSAKeyFile'.

-}

module Network.Wai.Protocol.UcamWebauth (
    module Network.Wai.Protocol.UcamWebauth
  , module Data.Lens.Internal
  , module Data.Settings.Internal
)   where

-- Prelude
import ClassyPrelude hiding (take, catMaybes)
import Data.Data
import GHC.Generics
import Data.Coerce

import Control.Applicative (empty, Alternative)
import Control.Error

import System.IO (withFile, IOMode(..))

-- Settings
import Data.Settings.Internal
import Data.Lens.Internal

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

-- Parsing
import Data.Attoparsec.Combinator (lookAhead)
import Data.Attoparsec.ByteString.Char8 hiding (count)
import qualified Data.Attoparsec.ByteString.Char8 as A

-- Map structures
import qualified Data.IntMap.Strict as I
import qualified Data.Map.Strict as M

-- JSON (Aeson)
import Data.Aeson (ToJSON, FromJSON)
import qualified Data.Aeson as A

-- Crypto
import Crypto.PubKey.RSA.Types
import Crypto.PubKey.RSA.PKCS15
import Crypto.Hash.Algorithms
import Data.X509
import Data.PEM

------------------------------------------------------------------------------
-- * Return type

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
-- * Top level functions

{-|
  'maybeAuthInfo' takes the 'AuthRequest' from its environment, and a 'ByteString' containing the @WLS@
  response, and if the response is valid, returns a 'UcamWebauthInfo' value.

  TODO When the errors returned can be usefully used, ensure this correctly returns a lifted
  'Either b (UcamWebauthInfo a)' response.
-}
maybeAuthInfo :: (FromJSON a, MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m) => Mod WAASettings -> ByteString -> m (UcamWebauthInfo a)
maybeAuthInfo mkConfig = getAuthInfo <=< maybeAuthCode mkConfig

{-|
  A helper function to parse and validate a response from a @WLS@.
-}
maybeAuthCode :: (FromJSON a, MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m) => Mod WAASettings -> ByteString -> m (SignedAuthResponse 'Valid a)
maybeAuthCode mkConfig = validateAuthResponse mkConfig <=< authCode

{-|
  Parse the response from a @WLS@.
-}
authCode :: (FromJSON a, MonadIO m, MonadPlus m) => ByteString -> m (SignedAuthResponse 'MaybeValid a)
authCode = liftMaybe . maybeResult . flip feed "" . parse ucamResponseParser

{-|
  Extract the 'ByteString' response from the @WLS@ in the full response header.
-}
lookUpWLSResponse :: Request -> Maybe ByteString
lookUpWLSResponse = join . M.lookup "WLS-Response" . M.fromList . queryString

------------------------------------------------------------------------------
-- * Core data types and associated functions

------------------------------------------------------------------------------
-- ** Type Synonyms

{-|
  A synonym to abstract much behaviour over a generic string type.
-}
type StringType = ByteString

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
                , ucamAKid :: Maybe KeyID -- ^ RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
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
                , ucamAStatus :: StatusCode -- ^ 3 digit status code (200 is success)
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
-- ** Typed representations of protocol data
{- $typed
  These types represent data such as the protocol version ('WLSVersion') that is 
  inherently typed but has a string representation in the protocol
-}

------------------------------------------------------------------------------
-- *** Protocol version

{-|
  Intended to be used as values, but Kind promotion means they can be used as types.
-}
data WLSVersion = WLS1 -- ^ Version 1 of the protocol. In the Raven implementation, failures use this version
                | WLS2 -- ^ Version 2
                | WLS3 -- ^ Version 3. Used for successful reponses by the Raven implementation
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show WLSVersion where
    show = displayWLSVersion

{-|
  Used for 'Show' instance.
-}
displayWLSVersion :: IsString a => WLSVersion -> a
displayWLSVersion WLS1 = "1"
displayWLSVersion WLS2 = "2"
displayWLSVersion WLS3 = "3"

{-|
  Like the 'Show' instance, but typed to 'StringType'.
-}
textWLSVersion :: WLSVersion -> StringType
textWLSVersion = displayWLSVersion

{-|
  A parser for the 'WLSVersion', as used by the 'AuthResponse' parser.
-}
wlsVersionParser :: Parser WLSVersion
wlsVersionParser = choice [
                            "3" *> pure WLS3
                          , "2" *> pure WLS2
                          , "1" *> pure WLS1
                          ]

{-|
  Actually parse a 'StringType' representing a 'WLSVersion'
-}
parseWLSVersion :: StringType -> Maybe WLSVersion
parseWLSVersion = maybeResult . parse wlsVersionParser

------------------------------------------------------------------------------
-- *** Representing booleans

{-|
  Representing 'Bool' as yes or no
-}
boolToYN :: IsString a => Bool -> a
boolToYN True = "yes"
boolToYN _ = "no"

{-|
  Monomorphic variant of 'boolToYN'
-}
boolToYNS :: Bool -> StringType
boolToYNS = boolToYN

{-|
  Representing yes or no
-}
trueOrFalse :: StringType -> Maybe Bool
trueOrFalse = maybeResult . parse ynToBool
    where
        ynToBool :: Parser Bool
        ynToBool = ("Y" <|> "y") *> "es" *> pure True
             <|> ("N" <|> "n") *> "o" *> pure False

------------------------------------------------------------------------------
-- *** Authentication types available

{-|
  An enumeration of valid authentication types. The protocol currently only defines one
  valid type.
-}
data AuthType = Pwd -- ^ pwd: Username and password
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show AuthType where
    show = displayAuthType

{-|
  Implement show generically
-}
displayAuthType :: IsString a => AuthType -> a
displayAuthType Pwd = "pwd"

{-|
  A parser for 'AuthType' data
-}
authTypeParser :: Parser AuthType
authTypeParser = "pwd" *> pure Pwd

{-|
  Actually parse 'AuthType' data
-}
parseAuthType :: StringType -> Maybe AuthType
parseAuthType = maybeResult . parse authTypeParser

------------------------------------------------------------------------------
-- *** Data possibly useful for authorization (ptags)

{-|
  This is only in protocol versions ≥ 3
-}
data Ptag = Current -- ^ User is current member of university
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show Ptag where
    show = displayPtag

{-|
  Generic 'Show' implementation
-}
displayPtag :: IsString a => Ptag -> a
displayPtag Current = "current"

{-|
  Parser representing a 'Ptag'
-}
ptagParser :: Parser Ptag
ptagParser = "current" *> pure Current

{-|
  Parse a 'Ptag'
-}
parsePtag :: StringType -> Maybe Ptag
parsePtag = maybeResult . parse ptagParser


------------------------------------------------------------------------------
-- *** HTTP response codes
{- $statusCodes
  A data type representing the HTTP status codes in the protocol. This is compatible
  with the 'Status' type, but using the algebraic data type makes working with it
  a little nicer.
-}

{-|
  The valid HTTP status codes, according to the protocol.

  'BadRequest400' is present as a default, if there is any other code received.
-}
data StatusCode = Ok200 -- ^ Authentication successful
                | Gone410 -- ^ Cancelled by the user
                | NoAuth510 -- ^ No mutually acceptable authentication types        
                | ProtoErr520 -- ^ Unsupported protocol version (Only for version 1)  
                | ParamErr530 -- ^ General request parameter error                    
                | NoInteract540 -- ^ Interaction would be required but has been blocked 
                | UnAuthAgent560 -- ^ Application agent is not authorised                
                | Declined570 -- ^ Authentication declined                            
                | BadRequest400 -- ^ Response not covered by any protocol responses
                deriving (Show, Read, Eq, Ord, Bounded, Generic, Typeable, Data)

instance Enum StatusCode where
    toEnum = fromMaybe BadRequest400 . flip lookup responseCodes
    fromEnum = statusCode . getStatus

{-|
  An 'IntMap' of 'Status' code numbers in the protocol to their typed representations.
-}
responseCodes :: IntMap StatusCode
responseCodes = I.fromList . fmap (statusCode . getStatus &&& id) $ [Ok200, Gone410, NoAuth510, ProtoErr520, ParamErr530, NoInteract540, UnAuthAgent560, Declined570]

{-|
  Convert to the 'Status' type, defaulting to 'badRequest400' for a bad request
-}
getStatus :: StatusCode -> Status
getStatus Ok200 = ok200
getStatus Gone410 = gone410
getStatus NoAuth510 = noAuth510
getStatus ProtoErr520 = protoErr520
getStatus ParamErr530 = paramErr530
getStatus NoInteract540 = noInteract540
getStatus UnAuthAgent560 = unAuthAgent560
getStatus Declined570 = declined570
getStatus _ = badRequest400

{-|
  A parser representing a typed 'Status' code within the protocol.
-}
responseCodeParser :: Parser StatusCode
responseCodeParser = toEnum <$> decimal

{-|
  Parse a 'Status' from a 'StringType'.
-}
parseResponseCode :: StringType -> Maybe StatusCode
parseResponseCode = maybeResult . parse responseCodeParser

------------------------------------------------------------------------------
-- *** 'Status' values

noAuth510, protoErr520, paramErr530, noInteract540, unAuthAgent560, declined570 :: Status
noAuth510 = mkStatus 510 "No mutually acceptable authentication types"
protoErr520 = mkStatus 520 "Unsupported protocol version (Only for version 1)"
paramErr530 = mkStatus 530 "General request parameter error"
noInteract540 = mkStatus 540 "Interaction would be required but has been blocked"
unAuthAgent560 = mkStatus 560 "Application agent is not authorised"
declined570 = mkStatus 570 "Authentication declined"

------------------------------------------------------------------------------
-- *** Keys

{-|
  The key id, representing the public key for the @WLS@, is composed of a subset of 'ByteString' identifiers

  TODO Do not export constructors
-}
newtype KeyID = KeyID { unKeyID :: ByteString }
    deriving (Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

instance Show KeyID where
    show = B.unpack . unKeyID

{-|
  The 'KeyID' can represent a restricted set of possible 'ByteString's, as per the protocol document,
  and this parser should only allow a valid representation.

  TODO Add tests to verify.
-}
kidParser :: Parser KeyID
kidParser = fmap (KeyID . B.pack) $ (:)
        <$> (satisfy . inClass $ "1-9")
        <*> (fmap catMaybes . A.count 7 . optionMaybe $ digit) <* (lookAhead . satisfy $ not . isDigit)

------------------------------------------------------------------------------
-- *** Time

{-|
  The modified UTCTime representation used in the protocol, based on RFC 3339. All
  time zones are 'utc'.

  TODO Do not export constructor or accessor.
-}
newtype UcamTime = UcamTime { unUcamTime :: Text }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Convert a 'UTCTime' to the protocol time representation, based on the 'utc' time zone.
-}
ucamTime :: UTCTime -> UcamTime
ucamTime = UcamTime . T.filter isAlphaNum . formatTimeRFC3339 . utcToZonedTime utc

{-|
  Using 'ucamTimeParser', work out the actual 'UTCTime' for further processing.

  If 'ucamTimeParser' succeeds it should always produce a valid result for 'parseTimeRFC3339'.
  As a result, 'parseTimeRFC3339' is extracted from the Maybe enviroment using 'fromMaybe' with
  'error'.
-}
utcTimeParser :: Parser UTCTime
utcTimeParser = zonedTimeToUTC . fromMaybe (error "Cannot parse time as RFC3339. There’s a bug in the parser.") . parseTimeRFC3339 . unUcamTime <$> ucamTimeParser

{-|
  This parses a 'StringType' into a 'UcamTime'
-}
ucamTimeParser :: Parser UcamTime
ucamTimeParser = do
        year <- take 4
        month <- take 2
        day <- take 2 <* "T"
        hour <- take 2
        minute <- take 2
        sec <- take 2 <* "Z"
        return . UcamTime . decodeUtf8 . mconcat $ [year, "-", month, "-", day, "T", hour, ":", minute, ":", sec, "Z"]

{-|
  Run 'utcTimeParser'
-}
parseUcamTime :: UcamTime -> Maybe UTCTime
parseUcamTime = maybeResult . parse utcTimeParser . encodeUtf8 . unUcamTime

------------------------------------------------------------------------------
-- * 'WAASettings' and lenses

{-|
  The settings for the application.

  TODO Do not export constructors or accessors, only lenses.
-}
data WAASettings = WAASettings {
                   _authAccepted :: [AuthType]
                 , _needReauthentication :: Maybe Bool
                 , _syncTimeOut :: NominalDiffTime
                 , _validKids :: [KeyID]
                 }
                 deriving (Show, Eq, Ord, Generic, Typeable, Data)

{-|
  Accepted authentication types by the protocol.

  Default @['Pwd']@
-}
authAccepted :: Lens' WAASettings [AuthType]
authAccepted f WAASettings{..} = (\_authAccepted -> WAASettings{_authAccepted, ..}) <$> f _authAccepted

{-|
  'Just' 'True' means ‘must reauthenticate’, 'Just' 'False' means ‘non-interactive’, 'Nothing' means anything goes.

  Default 'Nothing'
-}
needReauthentication :: Lens' WAASettings (Maybe Bool)
needReauthentication f WAASettings{..} = (\_needReauthentication -> WAASettings{_needReauthentication, ..}) <$> f _needReauthentication

{-|
  A timeout for the response validation.

  Default @40@ (seconds)
-}
syncTimeOut :: Lens' WAASettings NominalDiffTime
syncTimeOut f WAASettings{..} = (\_syncTimeOut -> WAASettings{_syncTimeOut, ..}) <$> f _syncTimeOut

{-|
  Valid 'KeyID' values for the protocol.

  Default @[]@ (/i.e./ no valid keys)
-}
validKids :: Lens' WAASettings [KeyID]
validKids f WAASettings{..} = (\_validKids -> WAASettings{_validKids, ..}) <$> f _validKids

------------------------------------------------------------------------------
-- ** Defaults

{-|
  The default @WAA@ settings. To accept the defaults, use

  > configWAA def

  or

  > configWAA . return $ ()

  To modify settings, use the provided lenses.
-}
configWAA :: Mod WAASettings -> WAASettings
configWAA = config WAASettings {
                   _authAccepted = [Pwd]
                 , _needReauthentication = Nothing
                 , _syncTimeOut = 40
                 , _validKids = empty
                 }

{-|
  To access settings, use the lenses. In the default case,

  @viewConfigWAA /lens/ def@
-}
viewConfigWAA :: Lens' WAASettings a -> Mod WAASettings -> a
{-# INLINE viewConfigWAA #-}
viewConfigWAA lens = view lens . configWAA

{-|
  TODO This is a default time. It doesn’t make much sense. Needs replacing.
-}
ancientUTCTime :: UTCTime
ancientUTCTime = UTCTime (ModifiedJulianDay 0) 0

------------------------------------------------------------------------------
-- * Marshalling to and from string representations

------------------------------------------------------------------------------
-- ** Printing

{-|
  Build a request header to send to the @WLS@, using an 'AuthRequest'
-}
ucamWebauthQuery :: ToJSON a => BlazeBuilder -- ^ The url of the @WLS@ api /e.g./ <https://raven.cam.ac.uk/auth/authenticate.html>
                             -> AuthRequest a
                             -> Header
ucamWebauthQuery url AuthRequest{..} = (hLocation, toByteString $ url <> theQuery)
    where
        theQuery :: BlazeBuilder
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
                   ("params", L.encode . A.encode <$> ucamQParams) :: (Text, Maybe LByteString)
                 ]

------------------------------------------------------------------------------
-- ** Parsing

{-|
  Parse the response from the @WLS@

  As a reminder, the 'MaybeValid' symbol indicates the response has not yet been verified.
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
                    ucamAIssue <- noBang utcTimeParser
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
            parsePrincipal :: StatusCode -> Parser (Maybe Text)
            parsePrincipal (statusCode . getStatus -> 200) = maybeBang . urlWrapText $ betweenBangs
            parsePrincipal _ = noBang . pure $ empty
            parseSso :: StatusCode -> Maybe AuthType -> Parser (Maybe [AuthType])
            parseSso (statusCode . getStatus -> 200) Nothing = noBang . fmap pure $ authTypeParser `sepBy1` ","
            parseSso _ _ = noBang . pure $ empty
            parseKidSig :: StatusCode -> Parser (Maybe KeyID, Maybe UcamBase64BS)
            parseKidSig (statusCode . getStatus -> 200) = curry (pure *** pure)
                                       <$> noBang kidParser
                                       <*> ucamB64parser
            parseKidSig _ = (,) <$> noBang (optionMaybe kidParser) <*> optionMaybe ucamB64parser
            {-|
              The Ucam-Webauth protocol uses @!@ characters to separate the fields in the response. Any @!@
              characters in the data itself must be url encoded. The representations used in this module
              meet this criterion.

              TODO Add tests to verify.
            -}
            betweenBangs :: Parser StringType
            betweenBangs = takeWhile1 (/= '!')

------------------------------------------------------------------------------
-- * Validation

{-|
  Validate the Authentication Response

  1. Validate the key id
  2. Validate the cryptographic signature against the relevant key
  3. Validate the issue time
  4. Validate the url is the same as that transmitted
  5. Validate the auth and sso values are valid

  The protocol requires a valid input, but 'ucamResponseParser' holds all the relevant logic
  as the only way to produce a 'SignedAuthResponse' is with the parser.

  This is the only way to produce a 'Valid' 'SignedAuthResponse', and therefore an 'AuthInfo'.
-}
validateAuthResponse :: forall a m . (MonadReader (AuthRequest a) m, MonadIO m, MonadPlus m)
                     => Mod WAASettings
                     -> SignedAuthResponse 'MaybeValid a
                     -> m (SignedAuthResponse 'Valid a)
validateAuthResponse mkConfig x@SignedAuthResponse{..} = do
        guard . validateKid mkConfig =<< liftMaybe ucamAKid
        guard <=< validateSig $ x
        guard <=< validateIssueTime mkConfig $ ucamAResponse
        guard <=< validateUrl $ ucamAResponse
        guard <=< validateAuthTypes mkConfig $ ucamAResponse
        return . makeValid $ x
        where
            makeValid :: SignedAuthResponse 'MaybeValid a -> SignedAuthResponse 'Valid a
            makeValid = coerce

------------------------------------------------------------------------------
-- ** Key ID

{-|
  Check the kid is valid
-}
validateKid :: Mod WAASettings -> KeyID -> Bool
validateKid = flip elem . viewConfigWAA validKids

------------------------------------------------------------------------------
-- ** Signature

{-|
  Validate the signature, getting the key using 'readRSAKeyFile'
-}
validateSig :: (MonadPlus m, MonadIO m) => SignedAuthResponse 'MaybeValid a -> m Bool
validateSig = validateSigKey readRSAKeyFile 

decodeRSAPubKey :: ByteString -- ^ The data representing a public key as PEM.
             -> Maybe PublicKey -- ^ @'Just' 'PublicKey'@ if RSA, 'Nothing' otherwise.
decodeRSAPubKey = hush . f
    where
        f :: ByteString -> Either String PublicKey
        f = getRSAKey . certPubKey . getCertificate <=< decodeSignedCertificate . pemContent <=< headErr "Empty list" <=< pemParseBS
        getRSAKey :: Alternative f => PubKey -> f PublicKey
        getRSAKey (PubKeyRSA x) = pure x
        getRSAKey _ = empty

{-|
  This assumes keys are PEM self-signed certificates in the ‘static’ directory, named

  @pubkey/key/.crt@

  where @/key/@ should be replaced by the 'KeyID' /e.g./ @pubkey2.crt@
-}
readRSAKeyFile :: (MonadIO m, Alternative m) => KeyID
                                             -> m PublicKey
readRSAKeyFile key = liftMaybe <=< liftIO . withFile ("static/pubkey" <> (B.unpack . unKeyID) key <> ".crt") ReadMode $ 
        pure . decodeRSAPubKey <=< B.hGetContents

validateSigKey :: MonadPlus m
               => (KeyID -> m PublicKey) -- ^ Get an RSA 'PublicKey' from somewhere, with the possibility of failing.
               -> SignedAuthResponse 'MaybeValid a
               -> m Bool -- ^ 'True' for a verified signature, 'False' for a verified invalid signature, and 'mzero' for an inability to validate
validateSigKey importKey SignedAuthResponse{..} = pure . rsaValidate =<< importKey =<< liftMaybe ucamAKid
    where
        rsaValidate :: PublicKey -> Bool
        rsaValidate key = verify (Just SHA1) key message signature
        message :: ByteString
        message = ucamAToSign
        signature :: ByteString
        signature = maybe mempty decodeUcamB64 ucamASig

------------------------------------------------------------------------------
-- ** Issue time

{-|
  Validate the time of issue is within 'syncTimeOut' of the current time.

  TODO Uses 'getCurrentTime'. There may be a better implementation.
-}
validateIssueTime :: (MonadIO m) => Mod WAASettings -> AuthResponse a -> m Bool
validateIssueTime mkConfig AuthResponse{..} = (viewConfigWAA syncTimeOut mkConfig >) . flip diffUTCTime ucamAIssue <$> liftIO getCurrentTime

------------------------------------------------------------------------------
-- ** Url

{-|
  Check the url parameter matches that sent in the 'AuthRequest'
-}
validateUrl :: (MonadReader (AuthRequest a) m) => AuthResponse a -> m Bool
validateUrl AuthResponse{..} = (==) ucamAUrl . ucamQUrl <$> ask

------------------------------------------------------------------------------
-- ** Authentication type

{-|
  Check the authentication type matches that sent.

  * If the iact variable is Yes, only return 'True' if the aauth value is acceptable.
  * If the iact variable is No, only return 'True' if sso contains a value that is acceptable.
  * If the iact variable is unset, return 'True' if there is an acceptable value in either field.
-}
validateAuthTypes :: forall a f . (Alternative f) => Mod WAASettings -> AuthResponse a -> f Bool
validateAuthTypes mkConfig AuthResponse{..} = maybe validateAnyAuth validateSpecificAuth . viewConfigWAA needReauthentication $ mkConfig
    where
        isAcceptableAuth :: AuthType -> Bool
        isAcceptableAuth = flip elem . viewConfigWAA authAccepted $ mkConfig
        anyAuth :: Maybe AuthType -> Maybe [AuthType] -> Bool
        anyAuth Nothing (Just x) = any isAcceptableAuth x
        anyAuth (Just x) Nothing = isAcceptableAuth x
        anyAuth _ _ = False
        validateAnyAuth :: f Bool
        validateAnyAuth = pure $ anyAuth ucamAAuth ucamASso
        validateSpecificAuth :: Bool -> f Bool
        validateSpecificAuth True = isAcceptableAuth <$> liftMaybe ucamAAuth
        validateSpecificAuth _ = any isAcceptableAuth <$> liftMaybe ucamASso

------------------------------------------------------------------------------
-- * Text encoding

{-|
  Ensure Base 64 text is not confused with other 'ByteString's
-}
newtype Base64BS = B64 { unB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Ensure Base 64 text modified to fit the Ucam-Webauth protocol is not confused with other 'ByteString's
-}
newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Convert to the protocol’s version of base64
-}
convertB64Ucam :: Base64BS -> UcamBase64BS
convertB64Ucam = UcamB64 . B.map camFilter . unB64
    where
        camFilter :: Char -> Char
        camFilter '+' = '-'
        camFilter '/' = '.'
        camFilter '=' = '_'
        camFilter x = x

{-|
  Convert from the protocol’s version of base64
-}
convertUcamB64 :: UcamBase64BS -> Base64BS
convertUcamB64 = B64 . B.map camFilter . unUcamB64
    where
        camFilter :: Char -> Char
        camFilter '-' = '+'
        camFilter '.' = '/'
        camFilter '_' = '='
        camFilter x = x

{-|
  This uses 'B.decodeLenient' internally.

  TODO It should not be a problem, if operating on validated input, but might be worth testing (low priority).
-}
decodeUcamB64 :: UcamBase64BS -> StringType
decodeUcamB64 = B.decodeLenient . unB64 . convertUcamB64

{-|
  Unlike decoding, this is fully pure.
-}
encodeUcamB64 :: StringType -> UcamBase64BS
encodeUcamB64 = convertB64Ucam . B64 . B.encode

{-|
  A parser to represent a Ucam-Webauth variant base64–encoded 'StringType' as a 'UcamBase64BS'
-}
ucamB64parser :: Parser UcamBase64BS
ucamB64parser = UcamB64 <$> takeWhile1 (ors [isAlphaNum, inClass "-._"])

{-|
  Ensure ASCII text is not confused with other 'ByteString's
-}
newtype ASCII = ASCII { unASCII :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Extract ascii text.

  TODO Use Haskell’s utf7 functions
-}
decodeASCII :: ASCII -> Text
decodeASCII = decodeUtf8 . B.filter isAlpha_ascii . unASCII

------------------------------------------------------------------------------
-- * Helper functions

{-|
  * If parser succeeds, wrap return value in 'Just'
  * If parser fails, return 'Nothing'.
-}
optionMaybe :: Parser a -> Parser (Maybe a)
optionMaybe = option empty . fmap pure

{-|
  Combines a list of predicates into a single predicate. /c.f./ 'all', which applies
  a single predicate to many items in a data structure.

  Simplifies to

  @ands :: ['Char' -> 'Bool'] -> 'Char' -> 'Bool'@
-}
ands :: (Applicative f, Traversable t, MonoFoldable (t a), Element (t a) ~ Bool)
    => t (f a) -> f Bool
ands = fmap and . sequenceA

{-|
  Combines a list of predicates into a single predicate. /c.f./ 'any', which applies
  a single predicate to many items in a data structure.

  Simplifies to

  @ors :: ['Char' -> 'Bool'] -> 'Char' -> 'Bool'@
-}
ors :: (Applicative f, Traversable t, MonoFoldable (t a), Element (t a) ~ Bool)
    => t (f a) -> f Bool
ors = fmap or . sequenceA

{-|
  Produce a predicate on 'Char' values, returning 'True' if none of the characters
  in the input list match, otherwise 'False'.

  Simplifies to

  @nots :: ['Char'] -> 'Char' -> 'Bool'@

  Opposite of 'oneOf'
-}
nots :: String -- ^ List of characters, @['Char']@
     -> Char -> Bool
nots = ands . fmap (/=)

{-|
  Produce a predicate on 'Char' values, returning 'True' if at least one of the
  characters in the input list match, otherwise 'False'.

  Simplifies to

  @oneOf :: ['Char'] -> 'Char' -> 'Bool'@

  Opposite of 'nots'.
-}
oneOf :: (Eq a, Traversable t, MonoFoldable (t Bool), Element (t Bool) ~ Bool)
    => t a -> a -> Bool
oneOf = ors . fmap (==)

{-|
  Lift a 'Maybe' value.
-}
liftMaybe :: Alternative f => Maybe a -> f a
liftMaybe = maybe empty pure
