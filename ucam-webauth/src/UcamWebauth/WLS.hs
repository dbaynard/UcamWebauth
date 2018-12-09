{-|
Module      : Protocol.UcamWebauth.WLS
Description : Encoding WLS responses in Ucam-Webauth protocol, from the University of Cambridge
Maintainer  : David Baynard <ucamwebauth@baynard.me>

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
  ( wlsEncode
  , wlsEncodeSign
  ) where

import           "aeson"              Data.Aeson (ToJSON)
import qualified "aeson"              Data.Aeson as A
import           "ucam-webauth-types" Data.ByteString.B64
import qualified "bytestring"         Data.ByteString.Builder as B
import qualified "bytestring"         Data.ByteString.Lazy as BSL
import           "base"               Data.Foldable (fold)
import           "base"               Data.List (intersperse)
import qualified "base"               Data.List.NonEmpty as NE (intersperse)
import           "base"               Data.Maybe
import           "text"               Data.Text (Text)
import           "text"               Data.Text.Encoding
import           "text"               Data.Text.Encoding.Error (lenientDecode)
import           "microlens"          Lens.Micro
import           "ucam-webauth-types" UcamWebauth.Data as X
import           "ucam-webauth-types" UcamWebauth.Data.Internal

wlsEncode :: ToJSON a => AuthResponse a -> Text
wlsEncode = textBuilder . wlsEncode'

wlsEncodeSign :: ToJSON a => MaybeValidResponse a -> Text
wlsEncodeSign = textBuilder . wlsEncodeSign'

textBuilder :: B.Builder -> Text
textBuilder = decodeUtf8With lenientDecode . BSL.toStrict . B.toLazyByteString

wlsEncode' :: ToJSON a => AuthResponse a -> B.Builder
wlsEncode' r = mconcat . intersperse "!" $
  [ r ^. ucamAVer       . to displayWLSVersion
  , r ^. ucamAStatus    . to (B.stringUtf8 . show . fromEnum)
  , r ^. ucamAMsg       . mTextEncoded
  , r ^. ucamAIssue     . encoded (unUcamTime . ucamTime)
  , r ^. ucamAId        . textEncoded
  , r ^. ucamAUrl       . textEncoded
  , r ^. ucamAPrincipal . mTextEncoded
  , r ^. ucamAPtags     . to (mconcat . intersperse "," . fmap displayPtag)
  , r ^. ucamAAuth      . to (maybe "" displayAuthType)
  , r ^. ucamASso       . to (maybe "" $ fold . NE.intersperse "," . fmap displayAuthType)
  , r ^. ucamALife      . to (maybe "" $ B.stringUtf8 . show . secondsFromTimePeriod)
  , r ^. ucamAParams    . to (maybe "" $ B.lazyByteString . unUcamB64L . encodeUcamB64L . A.encode)
  ]

wlsEncodeSign' :: ToJSON a => MaybeValidResponse a -> B.Builder
wlsEncodeSign' r = mconcat . intersperse "!" $
  [ r ^. ucamAResponse . to wlsEncode'
  , r ^. ucamAKid      . to (maybe "" $ B.byteString . unKeyID)
  , r ^. ucamASig      . to (maybe "" $ B.byteString . unUcamB64)
  ]

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
