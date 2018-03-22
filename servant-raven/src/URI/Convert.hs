{-|
Module      : URI.Convert
Description : Convert between network-uri and uri-bytestring
Maintainer  : David Baynard <davidbaynard@gmail.com>

Copyright   : David Baynard 2017
License     : Apache

Both "uri-bytestring" and "network-uri" provide a URI type.
The consensus seems to be the former is generally better (more strongly typed,
more maintained) but slightly — yet significantly — less flexible.
"http-api-data" uses the former . "servant" uses the latter (but also depends
on "http-api-data".)

This module enables interconversion between the two.

-}

{-# LANGUAGE
    PackageImports
  #-}

module URI.Convert
  ( UB.URI
  , uriByteString
  , uriByteStringRel
  , networkUri
  -- , uriByteString'
  -- , networkUri'
  ) where

import qualified "bytestring"     Data.ByteString.Char8 as B8
import           "errors"         Control.Error
import qualified "network-uri"    Network.URI as NU
import qualified "uri-bytestring" URI.ByteString as UB

uriByteString :: NU.URI -> Maybe (UB.URIRef UB.Absolute)
uriByteString = hush . UB.parseURI UB.laxURIParserOptions . B8.pack . flip (NU.uriToString id) ""

networkUri :: UB.URIRef UB.Absolute -> Maybe NU.URI
networkUri = NU.parseURI . B8.unpack . UB.serializeURIRef'

uriByteStringRel :: NU.URI -> Maybe (UB.URIRef UB.Relative)
uriByteStringRel = hush . UB.parseRelativeRef UB.laxURIParserOptions . B8.pack . flip (NU.uriToString id) ""

{-
 -uriByteString' :: NU.URI -> UB.URIRef UB.Absolute
 -uriByteString' NU.URI{..} = UB.URI{..}
 -  where
 -    uriScheme = Scheme . B8.pack $ NU.uriScheme
 -    uriAuthority = do
 -      NU.URIAuth{..} <- NU.uriAuthority
 -      let authorityUserInfo = uriUserInfo
 -        authorityHost = uriRegName
 -        authorityPort = uriPort
 -      pure UB.Authority{..}
 -    uriPath = B8.pack NU.uriPath
 -    uriQuery =
 -    uriFragment = pure . B8.pack $ NU.uriFragment
 -}
