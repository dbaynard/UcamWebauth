{-|
Module      : Network.Protocol.UcamWebauth
Description : The Ucam-Webauth protocol, from the University of Cambridge
Maintainer  : David Baynard <davidbaynard@gmail.com>

Key parts of the implementation of the protocol itself.

-}

module Network.Protocol.UcamWebauth (
    module Network.Protocol.UcamWebauth
  , module Network.Protocol.UcamWebauth.Data
  , module Network.Protocol.UcamWebauth.Internal
)   where

-- Prelude
import ClassyPrelude

import Network.Protocol.UcamWebauth.Internal
import Network.Protocol.UcamWebauth.Data

import Data.Coerce

import Control.Applicative (empty, Alternative)
import Control.Error hiding (catMaybes)

import System.IO (withFile, IOMode(..))

-- Settings
import Data.Settings.Internal
import Data.Lens.Internal

-- Character encoding
import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Base64.Lazy as L

import Data.Char (isAlphaNum)

import qualified Data.Text as T

import qualified Data.ByteString.Char8 as B

-- ByteString building
import Blaze.ByteString.Builder hiding (Builder)

-- Time
import Data.Time.RFC3339
import Data.Time.LocalTime
import Data.Time (secondsToDiffTime, diffUTCTime)

-- HTTP protocol
import Network.HTTP.Types

-- Parsing
import Data.Attoparsec.Combinator (lookAhead)
import Data.Attoparsec.ByteString.Char8 hiding (count, take)
import qualified Data.Attoparsec.ByteString.Char8 as A

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

------------------------------------------------------------------------------
-- *** Protocol version

{-|
  A parser for the 'WLSVersion', as used by the 'AuthResponse' parser.
-}
wlsVersionParser :: Parser WLSVersion
wlsVersionParser = choice [
                            "3" *> pure WLS3
                          , "2" *> pure WLS2
                          , "1" *> pure WLS1
                          ]

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
  A parser for 'AuthType' data
-}
authTypeParser :: Parser AuthType
authTypeParser = "pwd" *> pure Pwd

------------------------------------------------------------------------------
-- *** Data possibly useful for authorization (ptags)

{-|
  Parser representing a 'Ptag'
-}
ptagParser :: Parser Ptag
ptagParser = "current" *> pure Current

------------------------------------------------------------------------------
-- *** HTTP response codes

{-|
  A parser representing a typed 'Status' code within the protocol.
-}
responseCodeParser :: Parser StatusCode
responseCodeParser = toEnum <$> decimal

------------------------------------------------------------------------------
-- *** Keys

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
    where
        take = A.take

------------------------------------------------------------------------------
-- * 'WAASettings'

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
                 , _recentTime = UTCTime (ModifiedJulianDay 0) 0
                 , _applicationUrl = mempty
                 }

{-|
  To access settings, use the lenses. In the default case,

  @viewConfigWAA /lens/ def@
-}
viewConfigWAA :: Lens' WAASettings a -> Mod WAASettings -> a
{-# INLINE viewConfigWAA #-}
viewConfigWAA lens = view lens . configWAA

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
