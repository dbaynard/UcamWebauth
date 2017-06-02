{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ApplicativeDo #-}

module URI.ConvertSpec (main, spec) where

import "hspec" Test.Hspec
import "QuickCheck" Test.QuickCheck
import "quickcheck-instances" Test.QuickCheck.Instances
import "hspec" Test.Hspec.QuickCheck

import "servant-raven-server" URI.Convert

import "base" Data.Maybe
import "base" Control.Monad

import "generic-arbitrary" Test.QuickCheck.Arbitrary.Generic

import qualified "network-uri" Network.URI as NU
import qualified "uri-bytestring" URI.ByteString as UB

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
    describe "URI.Convert" $ do
        {-
         -prop "converts properly from network-uri" $
         -    \subj -> uriByteString subj `shouldSatisfy` isJust
         -}
        prop "converts properly from uri-bytestring" $
            \subj -> networkUri subj `shouldSatisfy` isJust
        prop "interconverts correctly" $
            \subj -> Just subj === do
                uriByteString <=< networkUri $ subj

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
  arbitrary = genericArbitrary
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
