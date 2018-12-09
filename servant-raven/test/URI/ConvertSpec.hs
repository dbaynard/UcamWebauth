{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , ApplicativeDo
  , FlexibleInstances
  , OverloadedStrings
  , QuasiQuotes
  , RecordWildCards
  #-}

module URI.ConvertSpec (spec) where

import           "base"                 Control.Monad
import qualified "bytestring"           Data.ByteString.Char8 as B8
import           "base"                 Data.Maybe
import           "hspec"                Test.Hspec
import           "QuickCheck"           Test.QuickCheck
import           "generic-arbitrary"    Test.QuickCheck.Arbitrary.Generic
import           "quickcheck-instances" Test.QuickCheck.Instances ()
import qualified "uri-bytestring"       URI.ByteString as UB
import           "uri-bytestring"       URI.ByteString.QQ
import                                  URI.Convert

spec :: Spec
spec = do

  {-
   -describe "URI.Convert" $ do
   -  prop "converts properly from network-uri" $
   -    \subj -> uriByteString subj `shouldSatisfy` isJust
   -  prop "converts properly from uri-bytestring" $
   -    \subj -> networkUri subj `shouldSatisfy` isJust
   -  prop "interconverts correctly" $
   -    \subj -> Just subj === do
   -      uriByteString <=< networkUri $ subj
   -}

  describe "networkUri" $ (`mapM_` sampleURIs) $ \x ->
    let disp = B8.unpack . UB.serializeURIRef' $ x in do
      it ("should convert " <> disp <> " from uri-bytestring")
      . (`shouldSatisfy` isJust) . networkUri
      $ x

  describe "interconverts" $ (`mapM_` sampleURIs) $ \x ->
    let disp = B8.unpack . UB.serializeURIRef' $ x in do
      it ("should interconvert " <> disp)
      . (Just x ===)
      $ do
        uriByteString <=< networkUri $ x


sampleURIs :: [UB.URIRef UB.Absolute]
sampleURIs =
  [ [uri|http://www.example.org/|]
  , [uri|http://www.example.org?foo=bar&|]
  , [uri|http://www.google.com:80/aclk?sa=l&ai=CChPOVvnoU8fMDI_QsQeE4oGwDf664-EF7sq01HqV1MMFCAAQAigDUO3VhpcDYMnGqYvApNgPoAGq3vbiA8gBAaoEKE_QQwekDUoMeW9IQghV4HRuzL_l-7vVjlML559kix6XOcC1c4Tb9xeAB76hiR2QBwGoB6a-Gw&sig=AOD64_3Ulyu0DcDsc1AamOIxq63RF9u4zQ&rct=j&q=&ved=0CCUQ0Qw&adurl=http://www.aruba.com/where-to-stay/hotels-and-resorts%3Ftid%3D122|]
  , [uri|http://www.example.org/foo#bar|]
  , [uri|http://www.example.org/foo#|]
  , [uri|https://www.example.org?listParam%5B%5D=foo,bar|]
  , [uri|https://www.example.org#only-fragment|]
  , [uri|https://www.example.org/weird%20path|]
  , [uri|https://www.example.org?listParam[]=foo,bar|]
  , [uri|http://www.example.org/.|]
  , [uri|http:/.|]
  ]

-- nonNetworkURIs :: [UB.URIRef UB.Absolute]
-- nonNetworkURIs =
--   [ [uri|https://user:pass:wo%20rd@www.example.org?foo=bar&foo=baz+quux#frag|]
--   ]

-- [relativeRef|verysimple|]
-- [relativeRef|./this:that/thap/sub?1=2|]

{-
 -instance Arbitrary NU.URIAuth where
 -  arbitrary = genericArbitrary
 -  shrink = genericShrink
 -
 -instance Arbitrary NU.URI where
 -  arbitrary = genericArbitrary
 -  shrink = genericShrink
 -}

instance Arbitrary UB.Port where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary UB.Host where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary UB.UserInfo where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary UB.Authority where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary UB.Scheme where
  arbitrary = UB.Scheme . B8.pack <$> genericArbitrary
  shrink = genericShrink

instance Arbitrary UB.Query where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary (UB.URIRef UB.Absolute) where
  arbitrary = do
    uriScheme <- arbitrary
    uriAuthority <- arbitrary
    uriPath <- arbitrary
    uriQuery <- arbitrary
    uriFragment <- arbitrary
    pure UB.URI{..}

