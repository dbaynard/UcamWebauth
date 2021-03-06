{-|
Module      : Data.ByteString.B64
Description : Base 64 ByteStrings (newtypes)
Maintainer  : David Baynard <ucamwebauth@baynard.me>
 -}

{-# LANGUAGE
    PackageImports
  , DataKinds
  , DeriveDataTypeable
  , DeriveGeneric
  , DerivingStrategies
  , GeneralizedNewtypeDeriving
  , OverloadedStrings
  , TypeInType
  #-}

module Data.ByteString.B64
  ( Base64UBS(..)
  , Base64UBSL(..)
  , UcamBase64BS(..)
  , UcamBase64BSL(..)
  , ASCII(..)
  ) where

import           "deepseq"    Control.DeepSeq (NFData)
import           "aeson"      Data.Aeson.Types
import           "bytestring" Data.ByteString (ByteString)
import qualified "bytestring" Data.ByteString.Lazy as BSL
import           "base"       Data.Data
import           "base"       Data.String
import           "text"       Data.Text (Text)
import           "text"       Data.Text.Encoding
import qualified "text"       Data.Text.Lazy.Encoding as TL
import           "base"       GHC.Generics

------------------------------------------------------------------------------
-- * Text encoding

{-|
  Ensure Base 64 URL text is not confused with other 'ByteString's
-}
newtype Base64UBS (tag :: k) = B64U { unB64U :: ByteString }
  deriving stock (Eq, Ord, Generic, Typeable, Data)
  deriving newtype (Show, Read, IsString, Monoid, Semigroup, NFData)

instance FromJSON (Base64UBS tag) where
  parseJSON = withObject "Base 64 URL ByteString" $ \v -> B64U . encodeUtf8
    <$> v .: "Base 64U ByteString"

instance ToJSON (Base64UBS tag) where
  toJSON = toJSON . decodeUtf8 . unB64U
  toEncoding = toEncoding . decodeUtf8 . unB64U

newtype Base64UBSL (tag :: k) = B64UL { unB64UL :: BSL.ByteString }
  deriving stock (Eq, Ord, Generic, Typeable, Data)
  deriving newtype (Show, Read, IsString, Monoid, Semigroup, NFData)

instance FromJSON (Base64UBSL tag) where
  parseJSON = withObject "Base 64 URL ByteString" $ \v -> B64UL . TL.encodeUtf8
    <$> v .: "Base 64U ByteString"

instance ToJSON (Base64UBSL tag) where
  toJSON = toJSON . TL.decodeUtf8 . unB64UL
  toEncoding = toEncoding . TL.decodeUtf8 . unB64UL

{-|
  Ensure Base 64 URL text modified to fit the Ucam-Webauth protocol is not confused with other 'ByteString's
-}
newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
  deriving stock (Eq, Ord, Generic, Typeable, Data)
  deriving newtype (Show, Read, IsString, Monoid, Semigroup, NFData)

instance FromJSON UcamBase64BS where
  parseJSON = withObject "Ucam Base 64 URL ByteString" $ \v -> UcamB64 . encodeUtf8
    <$> v .: "Ucam Base 64U ByteString"

instance ToJSON UcamBase64BS where
  toJSON = toJSON . decodeUtf8 . unUcamB64
  toEncoding = toEncoding . decodeUtf8 . unUcamB64

newtype UcamBase64BSL = UcamB64L { unUcamB64L :: BSL.ByteString }
  deriving stock (Eq, Ord, Generic, Typeable, Data)
  deriving newtype (Show, Read, IsString, Monoid, Semigroup, NFData)

{-|
  Ensure ASCII text is not confused with other 'ByteString's
-}
newtype ASCII = ASCII { unASCII :: Text }
  deriving stock (Eq, Ord, Generic, Typeable, Data)
  deriving newtype (Show, Read, IsString, Monoid, Semigroup, NFData)
