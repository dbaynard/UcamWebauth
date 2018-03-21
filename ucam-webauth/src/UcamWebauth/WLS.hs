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
  #-}

module UcamWebauth.WLS
  ( module UcamWebauth.WLS
  ) where

import           "aeson"              Data.Aeson (ToJSON)
import           "text"               Data.Text (Text)
import qualified "text"               Data.Text as T
import           "ucam-webauth-types" UcamWebauth.Data as X
import           "ucam-webauth-types" UcamWebauth.Data.Internal
import           "this"               UcamWebauth.Internal

wlsEncode :: ToJSON a => MaybeValidResponse a -> Text
wlsEncode r = T.intercalate "!"
  [
  ]
