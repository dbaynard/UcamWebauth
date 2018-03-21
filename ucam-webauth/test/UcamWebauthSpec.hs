{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , OverloadedStrings
  , QuasiQuotes
  , ScopedTypeVariables
  , TypeApplications
  , TypeSynonymInstances
  , FlexibleInstances
  #-}

module UcamWebauthSpec (spec) where

import "ucam-webauth-types"   Data.ByteString.B64
import "here"                 Data.String.Here
import "text"                 Data.Text (Text)
import "time-qq"              Data.Time.QQ as Q
import "hspec"                Test.Hspec
import "hspec"                Test.Hspec.QuickCheck
import "QuickCheck"           Test.QuickCheck
import "generic-arbitrary"    Test.QuickCheck.Arbitrary.Generic
import "quickcheck-instances" Test.QuickCheck.Instances ()
import "this"                 UcamWebauth
import "ucam-webauth-types"   UcamWebauth.Data.Internal
import "http-api-data"        Web.HttpApiData

spec :: Spec
spec = do
  describe "UcamWebauth" $ do
    it "should parse example response" $ do
      parseQueryParam @(MaybeValidResponse ()) exampleResponseText `shouldBe` Right exampleResponse
    it "should produce example response" $ do
      toQueryParam @(MaybeValidResponse ()) exampleResponse `shouldBe` exampleResponseText
    prop "should serialize with HttpApiData correctly" $ \(mvr :: MaybeValidResponse ()) ->
      (parseQueryParam . toQueryParam) mvr === Right mvr

instance Arbitrary a => Arbitrary (MaybeValidResponse a) where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary a => Arbitrary (AuthResponse a) where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary KeyID where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary WLSVersion where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary StatusCode where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary UcamBase64BS where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary Ptag where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary AuthType where
  arbitrary = genericArbitrary
  shrink = genericShrink

instance Arbitrary TimePeriod where
  arbitrary = genericArbitrary
  shrink = genericShrink

exampleResponse :: MaybeValidResponse ()
exampleResponse = SignedAuthResponse
  { _ucamAResponse = AuthResponse
    { _ucamAVer       = WLS3
    , _ucamAStatus    = Ok200
    , _ucamAMsg       = Nothing
    , _ucamAIssue     = [utcIso8601ms| 2017-05-15T17:23:11 |]
    , _ucamAId        = "oANAuhC9fZmMlZUPIm53y5vn"
    , _ucamAUrl       = "http://localhost:3000/foo/query"
    , _ucamAPrincipal = Just "test0244"
    , _ucamAPtags     = Just [Current]
    , _ucamAAuth      = Nothing
    , _ucamASso       = Just [Pwd]
    , _ucamALife      = Just (timePeriodFromSeconds 30380)
    , _ucamAParams    = Nothing
    }
  , _ucamAToSign = "3!200!!20170515T172311Z!oANAuhC9fZmMlZUPIm53y5vn!http://localhost:3000/foo/query!test0244!current!!pwd!30380!IlRoaXMgaXMgMTAwJSBvZiB0aGUgZGF0YSEgQW5kIGl04oCZcyByZWFsbHkgcXVpdGUgY29vbCI_"
  , _ucamAKid      = Just "901"
  , _ucamASig      = Just
    (UcamB64
      { unUcamB64 = "RzC9KZWALCSeK0n9885X4zzemHizuj8K.NOpt.n1hfRCTE2ZBgvJ-fBvT-PaL80cSFGpyCJgt9LvM4-peJzcidoKC6zhBEvG0QnlqWTLsphbIA0JmBRiOoeqyLYRVGwDEdLdacdsQRM.u7bik.enhbuN1-aIQCOdB5MutxtYiu4_"
      }
    )
  }

exampleResponseText :: Text
exampleResponseText = [here|
  3!200!!20170515T172311Z!oANAuhC9fZmMlZUPIm53y5vn!http://localhost:3000/foo/query!test0244!current!!pwd!30380!IlRoaXMgaXMgMTAwJSBvZiB0aGUgZGF0YSEgQW5kIGl04oCZcyByZWFsbHkgcXVpdGUgY29vbCI_!901!RzC9KZWALCSeK0n9885X4zzemHizuj8K.NOpt.n1hfRCTE2ZBgvJ-fBvT-PaL80cSFGpyCJgt9LvM4-peJzcidoKC6zhBEvG0QnlqWTLsphbIA0JmBRiOoeqyLYRVGwDEdLdacdsQRM.u7bik.enhbuN1-aIQCOdB5MutxtYiu4_
|]
