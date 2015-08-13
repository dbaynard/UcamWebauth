{-# OPTIONS_HADDOCK hide, not_here #-}

{-|
Module      : Network.Protocol.UcamWebauth.Parser
Description : Parsers for the UCam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Parser (
    module Network.Protocol.UcamWebauth.Parser
)   where

-- Prelude
import ClassyPrelude hiding (take)

import Network.Protocol.UcamWebauth.Internal
import Network.Protocol.UcamWebauth.Data

-- Parsing
import Data.Attoparsec.Combinator (lookAhead)
import Data.Attoparsec.ByteString.Char8 hiding (count)
import qualified Data.Attoparsec.ByteString.Char8 as A

-- HTTP protocol
import Network.HTTP.Types

-- Time
import Data.Time.RFC3339
import Data.Time.LocalTime
import Data.Time (secondsToDiffTime)

-- Character encoding
import Data.Char (isAlphaNum)
import qualified Data.ByteString.Base64 as B
import qualified Data.ByteString.Char8 as B

-- JSON (Aeson)
import Data.Aeson (FromJSON)
import qualified Data.Aeson as A


------------------------------------------------------------------------------
-- * 'Parser's

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
-- ** Helpers

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
  A parser for 'AuthType' data
-}
authTypeParser :: Parser AuthType
authTypeParser = "pwd" *> pure Pwd

{-|
  Parser representing a 'Ptag'
-}
ptagParser :: Parser Ptag
ptagParser = "current" *> pure Current

{-|
  A parser representing a typed 'Status' code within the protocol.
-}
responseCodeParser :: Parser StatusCode
responseCodeParser = toEnum <$> decimal

{-|
  The 'KeyID' can represent a restricted set of possible 'ByteString's, as per the protocol document,
  and this parser should only allow a valid representation.

  TODO Add tests to verify.
-}
kidParser :: Parser KeyID
kidParser = fmap (KeyID . B.pack) $ (:)
        <$> (satisfy . inClass $ "1-9")
        <*> (fmap catMaybes . A.count 7 . optionMaybe $ digit) <* (lookAhead . satisfy $ not . isDigit)

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
  A parser to represent a Ucam-Webauth variant base64–encoded 'StringType' as a 'UcamBase64BS'
-}
ucamB64parser :: Parser UcamBase64BS
ucamB64parser = UcamB64 <$> takeWhile1 (ors [isAlphaNum, inClass "-._"])


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

------------------------------------------------------------------------------
-- ** Representing booleans

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
