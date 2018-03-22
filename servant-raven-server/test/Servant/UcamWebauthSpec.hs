{-# LANGUAGE
    PackageImports
  , DataKinds
  , OverloadedStrings
  , QuasiQuotes
  , TypeApplications
  , TypeOperators
  #-}

module Servant.UcamWebauthSpec (main, spec) where

import "text"                 Data.Text (Text)
import "servant-server"       Servant
import "servant-raven-server" Servant.UcamWebauth
import "hspec"                Test.Hspec
import "uri-bytestring"       URI.ByteString.QQ

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "authURI" $ do
    it "should parse http://localhost:3001/authenticate correctly" $
      let lk = Proxy @("authenticate" :> Get '[JSON] Text)
      in
        (`shouldBe` "http://localhost:3001/authenticate")
        . authURI [uri|http://localhost:3001|] . linkURI
        $ safeLink lk lk
