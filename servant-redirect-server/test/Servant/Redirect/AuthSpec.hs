{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE PackageImports   #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators    #-}

module Servant.Redirect.AuthSpec (spec) where

import Servant.Redirect.Auth

import "hspec" Test.Hspec

import           "async" Control.Concurrent.Async
  (race_)
import           "exceptions" Control.Monad.Catch
  (throwM)
import qualified "unliftio-core" Control.Monad.IO.Unlift
  ()
import           "wai" Network.Wai
  (pathInfo)
import           "warp" Network.Wai.Handler.Warp
  (Settings, defaultSettings, runSettings, setLogger, setPort)
import           "servant-server" Servant                hiding
  (Handler(..), runHandler)
import qualified "servant-server" Servant
  (runHandler)

spec :: Spec
spec = do
  describe "Servant default Handler" $ do

    describe "runHandler" $ do

      it "pure" $ do
        Servant.runHandler (pure 200) `shouldReturn` Right (200 :: Int)

      it "throwError" $ do
        Servant.runHandler (throwError err400) `shouldReturn` Left @ServantErr @Int err400

      it "throwM" $ do
        Servant.runHandler (throwM err400) `shouldThrow` anyServantException

  describe "Servant.Raven.Auth" $ do

    describe "runHandler" $ do

      it "pure" $ do
        runHandler (pure 200) `shouldReturn` Right (200 :: Int)

      it "throwError" $ do
        runHandler (throwError err400) `shouldReturn` Left @ServantErr @Int err400

      it "throwM" $ do
        runHandler (throwM err400) `shouldReturn` Left @ServantErr @Int err400

    describe "withServer" . runIO . withServer $ do
      pure ()

withServer :: IO a -> IO ()
withServer f = race_ f $
  runSettings settings app

settings :: Settings
settings = setPort 8080
  . setLogger (\req st _mSize -> print st *> print (pathInfo req))
  $ defaultSettings

app :: Application
app = serve @API Proxy server

type API
    = "pure"       :> Get '[JSON] Int
 :<|> "throwError" :> Get '[JSON] Int
 :<|> "throwM"     :> Get '[JSON] Int

server :: Server API
server
    = pure 200
 :<|> throwError err400
 :<|> throwM err400

anyServantException :: Selector ServantErr
anyServantException = const True
