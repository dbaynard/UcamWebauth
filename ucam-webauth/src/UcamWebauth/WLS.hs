{-|
Module      : Protocol.UcamWebauth.WLS
Description : Encoding WLS responses in Ucam-Webauth protocol, from the University of Cambridge
Maintainer  : David Baynard <davidbaynard@gmail.com>

Encoding the WLS-Response contents.

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

This is useful for test suite and more.

-}

{-# LANGUAGE
    PackageImports
  , OverloadedStrings
  , PartialTypeSignatures
  #-}

module UcamWebauth.WLS
  ( module UcamWebauth.WLS
  ) where

import           "aeson"              Data.Aeson (ToJSON)
import qualified "aeson"              Data.Aeson as A
import           "ucam-webauth-types" Data.ByteString.B64
import qualified "bytestring"         Data.ByteString.Builder as B
import qualified "bytestring"         Data.ByteString.Lazy as BSL
import           "base"               Data.List (intersperse)
import           "base"               Data.Maybe
import           "text"               Data.Text (Text)
import           "text"               Data.Text.Encoding
import           "microlens"          Lens.Micro
import           "ucam-webauth-types" UcamWebauth.Data as X
import           "ucam-webauth-types" UcamWebauth.Data.Internal

wlsEncode :: ToJSON a => MaybeValidResponse a -> Text
wlsEncode r = decodeUtf8 . BSL.toStrict . B.toLazyByteString . mconcat . intersperse "!" $
    [ response ^. ucamAVer       . to displayWLSVersion
    , response ^. ucamAStatus    . to (B.stringUtf8 . show . fromEnum)
    , response ^. ucamAMsg       . mTextEncoded
    , response ^. ucamAIssue     . encoded (unUcamTime . ucamTime)
    , response ^. ucamAId        . textEncoded
    , response ^. ucamAUrl       . textEncoded
    , response ^. ucamAPrincipal . mTextEncoded
    , response ^. ucamAPtags     . to (maybe "" $ mconcat . intersperse "," . fmap displayPtag)
    , response ^. ucamAAuth      . to (maybe "" displayAuthType)
    , response ^. ucamASso       . to (maybe "" $ mconcat . intersperse "," . fmap displayAuthType)
    , response ^. ucamALife      . to (maybe "" $ B.stringUtf8 . show . secondsFromTimePeriod)
    , response ^. ucamAParams    . to (maybe "" $ B.lazyByteString . unUcamB64L . encodeUcamB64L . A.encode)
    , r        ^. ucamAKid       . to (maybe "" $ B.byteString . unKeyID)
    , r        ^. ucamASig       . to (maybe "" $ B.byteString . unUcamB64)
    ]
  where
    response = r ^. ucamAResponse

-- orBlank :: Getting r a B.Builder -> Getting r (Maybe a) B.Builder
-- orBlank g bcrb a = _

textEncoded :: Getting r Text B.Builder
textEncoded = encoded id

encoded :: ToJSON a => (a -> Text) -> Getting r a B.Builder
encoded f = to $ encodeUtf8Builder . f

mEncoded :: ToJSON a => (a -> Text) -> Getting r (Maybe a) B.Builder
mEncoded f = to $ encodeUtf8Builder . fromMaybe "" . fmap f

mTextEncoded :: Getting r (Maybe Text) B.Builder
mTextEncoded = mEncoded id

-- ucamTimeFormat :: (UTCTime )
-- ucamTimeFormat = B.stringUtf8 . formatTime defaultTimeLocale "%0Y%m%dT%H%M%SZ"
