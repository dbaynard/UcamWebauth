{-# OPTIONS_HADDOCK hide, not_here #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ApplicativeDo #-}

{-|
Module      : Network.Protocol.UcamWebauth.Parser
Description : Parsers for the UCam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Parser
  ( ucamResponseParser
  ) where

-- Prelude
import "ucam-webauth-types" Data.ByteString.B64
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data
import "ucam-webauth-types" Network.Protocol.UcamWebauth.Data.Internal

import "base" Control.Applicative
import "base" Control.Arrow ((***))
import "base" Data.Maybe

-- Parsing
import "attoparsec" Data.Attoparsec.Combinator (lookAhead)
import "attoparsec" Data.Attoparsec.ByteString.Char8 hiding (count, take)
import qualified "attoparsec" Data.Attoparsec.ByteString.Char8 as A

-- HTTP protocol
import "http-types" Network.HTTP.Types

-- Time
import "time" Data.Time.LocalTime
import "time" Data.Time (UTCTime)

-- Character encoding
import "text" Data.Text (Text)
import "text" Data.Text.Encoding
import "base" Data.Char (isAlphaNum)
import qualified "base64-bytestring" Data.ByteString.Base64 as B
import "bytestring" Data.ByteString (ByteString)
import qualified "bytestring" Data.ByteString.Char8 as B8

-- JSON (Aeson)
import "aeson" Data.Aeson (FromJSON)
import qualified "aeson" Data.Aeson as A


------------------------------------------------------------------------------
-- * 'Parser's

{-|
  Parse the response from the @WLS@

  As a reminder, the 'MaybeValid' symbol indicates the response has not yet been verified.
-}
ucamResponseParser :: forall a . FromJSON a => Parser (SignedAuthResponse 'MaybeValid a)
ucamResponseParser = do
        (_ucamAToSign, _ucamAResponse@AuthResponse{..}) <- noBang . match $ ucamAuthResponseParser
        (_ucamAKid, _ucamASig) <- parseKidSig _ucamAStatus
        _ <- endOfInput
        pure SignedAuthResponse{..}

    where
        ucamAuthResponseParser :: Parser (AuthResponse a)
        ucamAuthResponseParser = do
            _ucamAVer <- noBang wlsVersionParser
            _ucamAStatus <- noBang responseCodeParser
            _ucamAMsg <- maybeBang . urlWrapText $ betweenBangs
            _ucamAIssue <- noBang utcTimeParser
            _ucamAId <- noBang . urlWrapText $ betweenBangs
            _ucamAUrl <- noBang . urlWrapText $ betweenBangs
            _ucamAPrincipal <- parsePrincipal _ucamAStatus
            _ucamAPtags <- parsePtags _ucamAVer
            _ucamAAuth <- noBang . optionMaybe $ authTypeParser
            _ucamASso <- parseSso _ucamAStatus _ucamAAuth
            _ucamALife <- noBang . optionMaybe . fmap timePeriodFromSeconds $ decimal
            _ucamAParams <- A.decodeStrict . B.decodeLenient <$> betweenBangs
            pure AuthResponse{..}

        noBang :: Parser b -> Parser b
        noBang = (<* "!")

        -- urlWrap :: Functor f => f ByteString -> f ByteString
        -- urlWrap = fmap (urlDecode False)

        urlWrapText :: Functor f => f ByteString -> f Text
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
        parseKidSig (statusCode . getStatus -> 200) =
            curry (pure *** pure)
                <$> noBang kidParser
                <*> ucamB64parser
        parseKidSig _ = (,)
            <$> noBang (optionMaybe kidParser)
            <*> optionMaybe ucamB64parser

        {-|
          The Ucam-Webauth protocol uses @!@ characters to separate the fields in the response. Any @!@
          characters in the data itself must be url encoded. The representations used in this module
          meet this criterion.

          TODO Add tests to verify.
        -}
        betweenBangs :: Parser ByteString
        betweenBangs = takeWhile1 (/= '!')

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
kidParser = do
    frst <- satisfy . inClass $ "1-9"
    rest <- (fmap catMaybes . A.count 7 . optionMaybe $ digit) <* (lookAhead . satisfy $ not . isDigit)
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

{-|
  This parses a 'ByteString' into a 'UcamTime'
-}
ucamTimeParser :: Parser UcamTime
ucamTimeParser = do
    year <- A.take 4
    month <- A.take 2
    day <- A.take 2 <* "T"
    hour <- A.take 2
    minute <- A.take 2
    sec <- A.take 2 <* "Z"
    pure
        ( UcamTime . decodeUtf8 . mconcat $
        [year, "-", month, "-", day, "T", hour, ":", minute, ":", sec, "Z"]
        )

{-|
  A parser to represent a Ucam-Webauth variant base64–encoded 'ByteString' as a 'UcamBase64BS'
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
  Combines a list of predicates into a single predicate. /c.f./ 'any', which applies
  a single predicate to many items in a data structure.

  Simplifies to

  @ors :: ['Char' -> 'Bool'] -> 'Char' -> 'Bool'@
-}
ors :: (Traversable t, Applicative f)
    => t (f Bool) -> f Bool
ors = fmap or . sequenceA
