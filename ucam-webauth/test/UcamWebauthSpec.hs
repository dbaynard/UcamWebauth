{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE
    PackageImports
  , AllowAmbiguousTypes
  , FlexibleInstances
  , NamedFieldPuns
  , OverloadedLists
  , OverloadedStrings
  , QuasiQuotes
  , RecordWildCards
  , ScopedTypeVariables
  , TypeApplications
  , TypeOperators
  , TypeSynonymInstances
  #-}

module UcamWebauthSpec (spec) where

import           "aeson"                Data.Aeson.Types hiding ((.=))
import           "base"                 Data.Bits
import qualified "bytestring"           Data.ByteString as BS
import           "ucam-webauth-types"   Data.ByteString.B64
import qualified "bytestring"           Data.ByteString.Char8 as B8
import           "base"                 Data.Char
import           "base"                 Data.Maybe
import           "here"                 Data.String.Here
import           "text"                 Data.Text (Text)
import           "text"                 Data.Text.Encoding
import qualified "text"                 Data.Text as T
import           "time"                 Data.Time
import           "time-qq"              Data.Time.QQ as Q
import           "generic-random"       Generic.Random
import           "microlens"            Lens.Micro
import           "microlens-mtl"        Lens.Micro.Mtl
import           "hspec"                Test.Hspec
import           "hspec"                Test.Hspec.QuickCheck
import           "QuickCheck"           Test.QuickCheck
import           "quickcheck-instances" Test.QuickCheck.Instances ()
import           "this"                 UcamWebauth
import           "ucam-webauth-types"   UcamWebauth.Data.Internal
import           "http-api-data"        Web.HttpApiData

spec :: Spec
spec = do
  describe "UcamWebauth" $ do
    it "should parse example response" $ do
      parseQueryParam @(AuthResponse Text) exampleResponseText `shouldBe` Right exampleResponse
    it "should parse example signed response" $ do
      parseQueryParam @(MaybeValidResponse Text) exampleSignedResponseText `shouldBe` Right exampleSignedResponse
    it "should produce example response" $ do
      toQueryParam @(AuthResponse Text) exampleResponse `shouldBe` exampleResponseText
    it "should produce example signed response" $ do
      toQueryParam @(MaybeValidResponse Text) exampleSignedResponse `shouldBe` exampleSignedResponseText
    modifyMaxSuccess (const 1000) $ prop_HttpApiData @(AuthResponse Text)
    modArgs $ prop_HttpApiData @(MaybeValidResponse Text)

modArgs :: SpecWith a -> SpecWith a
modArgs = modifyMaxSuccess (const 100) . modifyMaxDiscardRatio (const 1) . modifyMaxSize (const 1)

prop_HttpApiData
  :: forall a .
    ( Arbitrary a
    , Eq a
    , Show a
    , ToHttpApiData a
    , FromHttpApiData a
    )
  => Spec
prop_HttpApiData = prop "should serialize with HttpApiData correctly" $ \(h :: a) ->
  let qp = toQueryParam h in counterexample (T.unpack qp) $
    parseQueryParam qp === Right h

instance (ToJSON a, FromJSON a, Arbitrary a) => Arbitrary (MaybeValidResponse a) where
  arbitrary = do
    x <- genericArbitraryU `suchThat` \a -> and @[]
      [ notElem @[] (a ^. ucamASig) [Just "", Nothing]
      , isNothing (a ^. ucamASig) || isJust (a ^. ucamAKid)
      ]
    pure $ x &~ do
      ucamAToSign .= encodeUtf8 (toQueryParam (x ^. ucamAResponse))
  shrink = genericShrink

instance (ToJSON a, FromJSON a, Arbitrary a) => Arbitrary (AuthResponse a) where
  arbitrary = do
    x <- genericArbitraryU `suchThat` \a -> and @[]
      [ fromMaybe True $ a ^? ucamAPrincipal . _Just . to (T.all (/= '!'))
      , fromMaybe True $ a ^? ucamAMsg . _Just . to (T.all (/= '!'))
      , a ^. ucamAId . to (T.all (/= '!'))
      , a ^. ucamAUrl . to (T.all (/= '!'))
      , isJust (a ^. ucamAAuth) `xor` isJust (a ^. ucamASso)
      , a ^. ucamAPrincipal /= Just ""
      , a ^. ucamAMsg /= Just ""
      ]
    pure $ x &~ do
      ucamAIssue . dayTime %= fromInteger . round
  shrink = genericShrink

dayTime :: UTCTime `Lens'` DiffTime
dayTime f UTCTime{..} = (\x -> UTCTime{utctDayTime = x, ..}) <$> f utctDayTime
{-# INLINE dayTime #-}

instance Arbitrary KeyID where
  arbitrary = genericArbitraryU `suchThat` \(KeyID a) -> and @[]
    [ BS.length a & \x -> x >= 1 && x <= 8
    , B8.all isDigit a
    , B8.head a /= '0'
    ]
  shrink = genericShrink

instance Arbitrary WLSVersion where
  arbitrary = pure WLS3

instance Arbitrary StatusCode where
  arbitrary = pure Ok200

instance Arbitrary UcamBase64BS where
  arbitrary = encodeUcamB64 <$> arbitrary
  shrink = genericShrink

instance Arbitrary Ptag where
  arbitrary = genericArbitraryU
  shrink = genericShrink

instance Arbitrary AuthType where
  arbitrary = genericArbitraryU
  shrink = genericShrink

instance Arbitrary TimePeriod where
  arbitrary = timePeriodFromSeconds . secondsFromTimePeriod <$> genericArbitraryU `suchThat` (>= 0)

  shrink = genericShrink

exampleSignedResponse :: MaybeValidResponse Text
exampleSignedResponse = SignedAuthResponse
  { _ucamAResponse = AuthResponse
    { _ucamAVer       = WLS3
    , _ucamAStatus    = Ok200
    , _ucamAMsg       = Nothing
    , _ucamAIssue     = [utcIso8601ms| 2017-05-15T17:23:11 |]
    , _ucamAId        = "oANAuhC9fZmMlZUPIm53y5vn"
    , _ucamAUrl       = "http://localhost:3000/foo/query"
    , _ucamAPrincipal = Just "test0244"
    , _ucamAPtags     = [Current]
    , _ucamAAuth      = Nothing
    , _ucamASso       = Just [Pwd]
    , _ucamALife      = Just (timePeriodFromSeconds 30380)
    , _ucamAParams    = Just "This is 100% of the data! And it’s really quite cool"
    }
  , _ucamAToSign = "3!200!!20170515T172311Z!oANAuhC9fZmMlZUPIm53y5vn!http://localhost:3000/foo/query!test0244!current!!pwd!30380!IlRoaXMgaXMgMTAwJSBvZiB0aGUgZGF0YSEgQW5kIGl04oCZcyByZWFsbHkgcXVpdGUgY29vbCI_"
  , _ucamAKid      = Just "901"
  , _ucamASig      = Just
    (UcamB64
      { unUcamB64 = "RzC9KZWALCSeK0n9885X4zzemHizuj8K.NOpt.n1hfRCTE2ZBgvJ-fBvT-PaL80cSFGpyCJgt9LvM4-peJzcidoKC6zhBEvG0QnlqWTLsphbIA0JmBRiOoeqyLYRVGwDEdLdacdsQRM.u7bik.enhbuN1-aIQCOdB5MutxtYiu4_"
      }
    )
  }

exampleResponse :: AuthResponse Text
exampleResponse = AuthResponse
  { _ucamAVer       = WLS3
  , _ucamAStatus    = Ok200
  , _ucamAMsg       = Nothing
  , _ucamAIssue     = [utcIso8601ms| 2017-05-15T17:23:11 |]
  , _ucamAId        = "oANAuhC9fZmMlZUPIm53y5vn"
  , _ucamAUrl       = "http://localhost:3000/foo/query"
  , _ucamAPrincipal = Just "test0244"
  , _ucamAPtags     = [Current]
  , _ucamAAuth      = Nothing
  , _ucamASso       = Just [Pwd]
  , _ucamALife      = Just (timePeriodFromSeconds 30380)
  , _ucamAParams    = Just "This is 100% of the data! And it’s really quite cool"
  }

exampleSignedResponseText :: Text
exampleSignedResponseText = exampleResponseText <> [here|
  !901!RzC9KZWALCSeK0n9885X4zzemHizuj8K.NOpt.n1hfRCTE2ZBgvJ-fBvT-PaL80cSFGpyCJgt9LvM4-peJzcidoKC6zhBEvG0QnlqWTLsphbIA0JmBRiOoeqyLYRVGwDEdLdacdsQRM.u7bik.enhbuN1-aIQCOdB5MutxtYiu4_
|]

exampleResponseText :: Text
exampleResponseText = [here|
  3!200!!20170515T172311Z!oANAuhC9fZmMlZUPIm53y5vn!http://localhost:3000/foo/query!test0244!current!!pwd!30380!IlRoaXMgaXMgMTAwJSBvZiB0aGUgZGF0YSEgQW5kIGl04oCZcyByZWFsbHkgcXVpdGUgY29vbCI_
|]
