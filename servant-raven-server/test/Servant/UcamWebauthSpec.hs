{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}

module Servant.UcamWebauthSpec (main, spec) where

import "hspec" Test.Hspec
import "servant-raven-server" Servant.UcamWebauth
import "servant-server" Servant
import "text" Data.Text (Text)
import "uri-bytestring" URI.ByteString.QQ

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
