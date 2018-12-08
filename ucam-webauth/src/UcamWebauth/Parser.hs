{-# OPTIONS_HADDOCK hide, not_here #-}
{-# LANGUAGE
    PackageImports
  , ApplicativeDo
  , DataKinds
  , OverloadedStrings
  , RecordWildCards
  , ScopedTypeVariables
  , ViewPatterns
  #-}

{-|
Module      : UcamWebauth.Parser
Description : Parsers for the UCam-Webauth protocol
Maintainer  : David Baynard <ucamwebauth@baynard.me>

-}

module UcamWebauth.Parser
  ( ucamResponseParser
  , ucamAuthResponseParser
  ) where

import           "base"               Control.Applicative
import           "parser-combinators" Control.Applicative.Combinators.NonEmpty
import           "base"               Control.Arrow ((***))
import           "aeson"              Data.Aeson (FromJSON)
import qualified "aeson"              Data.Aeson as A
import qualified "attoparsec"         Data.Attoparsec.ByteString.Char8 as A
import           "attoparsec"         Data.Attoparsec.ByteString.Char8 hiding (count, take, sepBy1)
import           "attoparsec"         Data.Attoparsec.Combinator (lookAhead)
import           "bytestring"         Data.ByteString (ByteString)
import           "ucam-webauth-types" Data.ByteString.B64
import qualified "bytestring"         Data.ByteString.Char8 as B8
import           "base"               Data.Char (isAlphaNum)
import           "base"               Data.List.NonEmpty (NonEmpty)
import           "base"               Data.Maybe
import           "text"               Data.Text (Text)
import           "text"               Data.Text.Encoding
import           "time"               Data.Time (UTCTime)
import           "time"               Data.Time.LocalTime
import           "http-types"         Network.HTTP.Types
import           "ucam-webauth-types" UcamWebauth.Data
import           "ucam-webauth-types" UcamWebauth.Data.Internal

------------------------------------------------------------------------------
-- * 'Parser's

{-|
  Parse the response from the @WLS@

  As a reminder, the 'MaybeValid' symbol indicates the response has not yet been verified.
-}
ucamResponseParser :: FromJSON a => Parser (MaybeValidResponse a)
ucamResponseParser = do
  (_ucamAToSign, _ucamAResponse@AuthResponse{..}) <- noBang . match $ ucamAuthResponseParser
  (_ucamAKid, _ucamASig) <- parseKidSig _ucamAStatus <?> "A Kid signature"
  _ <- endOfInput
  pure SignedAuthResponse{..}

ucamAuthResponseParser :: FromJSON a => Parser (AuthResponse a)
ucamAuthResponseParser = do
  _ucamAVer       <- noBang wlsVersionParser
  _ucamAStatus    <- noBang responseCodeParser
  _ucamAMsg       <- maybeBang . urlWrapText $ (betweenBangs <?> "Msg")
  _ucamAIssue     <- noBang utcTimeParser
  _ucamAId        <- fmap (fromMaybe "") . maybeBang . urlWrapText $ (betweenBangs <?> "Id")
  _ucamAUrl       <- fmap (fromMaybe "") . maybeBang . urlWrapText $ (betweenBangs <?> "Url")
  _ucamAPrincipal <- parsePrincipal _ucamAStatus
  _ucamAPtags     <- parsePtags _ucamAVer
  _ucamAAuth      <- maybeBang $ authTypeParser
  _ucamASso       <- parseSso _ucamAStatus _ucamAAuth
  _ucamALife      <- maybeBang . fmap timePeriodFromSeconds $ decimal
  _ucamAParams    <- A.decodeStrict . decodeUcamB64 . UcamB64 <$> betweenBangs <|> pure empty <?> "Parameters"
  pure AuthResponse{..}

noBang :: Parser b -> Parser b
noBang = (<* "!")

-- urlWrap :: Functor f => f ByteString -> f ByteString
-- urlWrap = fmap (urlDecode False)

urlWrapText :: Functor f => f ByteString -> f Text
urlWrapText = fmap (decodeUtf8 . urlDecode False)

maybeBang :: Parser b -> Parser (Maybe b)
maybeBang = noBang . optional

parsePtags :: WLSVersion -> Parser [Ptag]
parsePtags WLS3 = noBang $ ptagParser `sepBy` ","
parsePtags _    = pure empty

parsePrincipal :: StatusCode -> Parser (Maybe Text)
parsePrincipal (statusCode . getStatus -> 200) = maybeBang . urlWrapText $ (betweenBangs <?> "Principal")
parsePrincipal _                               = noBang empty <?> "Empty principal"

parseSso :: StatusCode -> Maybe AuthType -> Parser (Maybe (NonEmpty AuthType))
parseSso (statusCode . getStatus -> 200) Nothing = (maybeBang $ authTypeParser `sepBy1` ",") <?> "Sso"
parseSso _ _                                     = noBang (pure empty <?> "Empty Sso")

parseKidSig :: StatusCode -> Parser (Maybe KeyID, Maybe UcamBase64BS)
parseKidSig (statusCode . getStatus -> 200) =
  curry (pure *** pure)
    <$> noBang kidParser
    <*> ucamB64parser
parseKidSig _ = (,)
  <$> noBang (optional kidParser)
  <*> optional ucamB64parser

{-|
  The Ucam-Webauth protocol uses @!@ characters to separate the fields in the response. Any @!@
  characters in the data itself must be url encoded. The representations used in this module
  meet this criterion.

  TODO Add tests to verify.
-}
betweenBangs :: Parser ByteString
betweenBangs = takeWhile1 (/= '!')
  <?> "Missing field between !"

------------------------------------------------------------------------------
-- ** Helpers

{-|
  A parser for the 'WLSVersion', as used by the 'AuthResponse' parser.
-}
wlsVersionParser :: Parser WLSVersion
wlsVersionParser = choice
  [ "3" *> pure WLS3
  , "2" *> pure WLS2
  , "1" *> pure WLS1
  ]
  <?> "WLS version"

{-|
  A parser for 'AuthType' data
-}
authTypeParser :: Parser AuthType
authTypeParser = "pwd" *> pure Pwd
  <?> "AuthType"

{-|
  Parser representing a 'Ptag'
-}
ptagParser :: Parser Ptag
ptagParser = "current" *> pure Current
  <?> "PTag"

{-|
  A parser representing a typed 'Status' code within the protocol.
-}
responseCodeParser :: Parser StatusCode
responseCodeParser = toEnum <$> decimal
  <?> "Response code"

{-|
  The 'KeyID' can represent a restricted set of possible 'ByteString's, as per the protocol document,
  and this parser should only allow a valid representation.

  TODO Add tests to verify.
-}
kidParser :: Parser KeyID
kidParser = (<?> "Key id") $ do
  frst <- satisfy . inClass $ "1-9"
  rest <- (fmap catMaybes . A.count 7 . optional $ digit) <* (lookAhead . satisfy $ not . isDigit)
  pure (KeyID . B8.pack $ frst : rest)

{-|
  Using 'ucamTimeParser', work out the actual 'UTCTime' for further processing.

  If 'ucamTimeParser' succeeds it should always produce a valid result for 'parseTimeRFC3339'.
  As a result, 'parseTimeRFC3339' is extracted from the Maybe enviroment using 'fromMaybe' with
  'error'.
-}
utcTimeParser :: Parser UTCTime
utcTimeParser = let er = error "Cannot parse time as RFC3339. There’s a bug in the parser." in
  zonedTimeToUTC . fromMaybe er . zonedUcamTime <$> ucamTimeParser
  <?> "UTCTime"

{-|
  This parses a 'ByteString' into a 'UcamTime'
-}
ucamTimeParser :: Parser UcamTime
ucamTimeParser = do
  year   <- A.take 4
  month  <- A.take 2
  day    <- A.take 2 <* "T"
  hour   <- A.take 2
  minute <- A.take 2
  sec    <- A.take 2 <* "Z"
  pure
    ( UcamTime . decodeUtf8 . mconcat $
      [year, "-", month, "-", day, "T", hour, ":", minute, ":", sec, "Z"]
    ) <?> "UcamWebauth Time"

{-|
  A parser to represent a Ucam-Webauth variant base64–encoded 'ByteString' as a 'UcamBase64BS'
-}
ucamB64parser :: Parser UcamBase64BS
ucamB64parser = UcamB64 <$> takeWhile1 (ors [isAlphaNum, inClass "-._"])
  <?> "UcamWebauth Base 64 string"

------------------------------------------------------------------------------
-- * Helper functions

{-|
  Combines a list of predicates into a single predicate. /c.f./ 'any', which applies
  a single predicate to many items in a data structure.

  Simplifies to

  @ors :: ['Char' -> 'Bool'] -> 'Char' -> 'Bool'@
-}
ors
  :: (Traversable t, Applicative f)
  => t (f Bool) -> f Bool
ors = fmap or . sequenceA
