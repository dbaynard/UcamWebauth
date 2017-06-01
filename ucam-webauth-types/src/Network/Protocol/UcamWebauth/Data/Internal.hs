{-# OPTIONS_HADDOCK hide, not_here #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeInType #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE NumDecimals #-}
{-# LANGUAGE PatternSynonyms #-}

{-|
Module      : Network.Protocol.UcamWebauth.Internal
Description : Internal use for Ucam Webauth data types
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Data.Internal
  ( UcamWebauthInfo(..)

  , AuthRequest(..)

  , SignedAuthResponse(..)

  , IsValid(..)

  , AuthResponse(..)

  , extractAuthInfo

  , WLSVersion(..)
  , displayWLSVersion
  , bsDisplayWLSVersion

  , AuthType(..)
  , displayAuthType

  , Ptag(..)
  , displayPtag

  , StatusCode(..)
  , responseCodes
  , getStatus
  , noAuth510
  , protoErr520
  , paramErr530
  , noInteract540
  , unAuthAgent560
  , declined570

  , YesNo(..)
  , displayYesNo
  , bsDisplayYesNo

  , YesOnly(YesOnly)
  , displayYesOnly
  , bsDisplayYesOnly

  , KeyID(..)

  , UcamTime(..)
  , TimePeriod(..)
  , secondsFromTimePeriod
  , timePeriodFromSeconds

  , WAAState(..)

  , WAASettings(..)
  , SetWAA
  , configWAA

  , Base64UBS(..)
  , Base64UBSL(..)
  , UcamBase64BS(..)
  , UcamBase64BSL(..)
  , ASCII(..)
  ) where

-- Prelude
import "base" Data.Data
import "base" GHC.Generics
import "base" Control.Applicative
import "base" Data.String
import "base" Data.Semigroup
import "containers" Data.IntMap (IntMap)
import qualified "containers" Data.IntMap as IntMap
import "errors" Control.Error
import "base" Control.Arrow ((&&&))
import "mtl" Control.Monad.State

-- Character encoding

import "bytestring" Data.ByteString (ByteString)
import qualified "bytestring" Data.ByteString.Char8 as B
import qualified "bytestring" Data.ByteString.Lazy as BSL
import "text" Data.Text (Text)
import "text" Data.Text.Encoding
import qualified "text" Data.Text.Lazy.Encoding as TL

import "aeson" Data.Aeson.Types

-- Time
import "time" Data.Time

-- HTTP protocol
import "http-types" Network.HTTP.Types

------------------------------------------------------------------------------
-- * Core data types and associated functions

------------------------------------------------------------------------------
-- ** Return type

{-|
  'UcamWebauthInfo' is returned from this module. The parameter 'a' represents data sent
  in the initial connection, that must be returned. The constructor and accessors are *not*
  exported from the module, to present an abstract API.
-}
data UcamWebauthInfo a = AuthInfo
    { _approveUniq :: (UTCTime, Text)
    , _approveUser :: Text
    , _approveAttribs :: [Ptag]
    , _approveLife :: Maybe TimePeriod
    , _approveParams :: Maybe a
    } deriving (Show, Eq, Ord, Generic, Generic1, Typeable, Data)

instance ToJSON a => ToJSON (UcamWebauthInfo a)
instance FromJSON a => FromJSON (UcamWebauthInfo a)

------------------------------------------------------------------------------
-- ** Request and response
{- $request
  The handshake between the @WLS@ and @WAA@ are represented using the 'AuthRequest'
  and 'SignedAuthResponse' data types. The 'AuthResponse' type represents the
  content of a 'SignedAuthResponse'. Constructors and accessors are not exported,
  and the 'AuthRequest' should be build using the smart constructors provided.
-}

{-|
  An 'AuthRequest' is constructed by the @WAA@, using the constructor functions
  of this module. The parameter represents data to be returned to the application
  after authentication.
-}
data AuthRequest a = MakeAuthRequest
    { _ucamQVer :: WLSVersion
    , _ucamQUrl :: Text
    , _ucamQDesc :: Maybe ASCII
    , _ucamQAauth :: Maybe [AuthType]
    , _ucamQIact :: Maybe YesNo
    , _ucamQMsg :: Maybe Text
    , _ucamQParams :: Maybe a
    , _ucamQDate :: Maybe UTCTime
    , _ucamQFail :: Maybe YesOnly
    } deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  A 'SignedAuthResponse' represents the data returned by the @WLS@, including a
  representation of the content returned (in the 'AuthResponse' data type), and
  the cryptographic signature, for verification.

  The phantom parameter 'valid' corr
-}
data SignedAuthResponse (valid :: IsValid) a = SignedAuthResponse
    { _ucamAResponse :: AuthResponse a
    , _ucamAToSign :: ByteString
    , _ucamAKid :: Maybe KeyID
    , _ucamASig :: Maybe UcamBase64BS
    } deriving (Show, Eq, Ord, Generic, Generic1, Typeable, Data)

{-|
  The intended use of this is with 'IsValid' as a kind (requires the 'DataKinds' extension).
  The data constructors 'Valid' and 'MaybeValid' are now type constructors, which indicate the
  validity of a 'SignedAuthResponse'.

  This is not exported.
-}
data IsValid
    = MaybeValid
    | Valid
    deriving (Show, Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

{-|
  An 'AuthResponse' represents the content returned by the @WLS@. The validation
  machinery in this module returns the required data as a 'UcamWebauthInfo' value.
-}
data AuthResponse a = AuthResponse
    { _ucamAVer :: WLSVersion
    , _ucamAStatus :: StatusCode
    , _ucamAMsg :: Maybe Text
    , _ucamAIssue :: UTCTime
    , _ucamAId :: Text
    , _ucamAUrl :: Text
    , _ucamAPrincipal :: Maybe Text
    , _ucamAPtags :: Maybe [Ptag]
    , _ucamAAuth :: Maybe AuthType
    , _ucamASso :: Maybe [AuthType]
    , _ucamALife :: Maybe TimePeriod
    , _ucamAParams :: Maybe a
    } deriving (Show, Eq, Ord, Generic, Generic1, Typeable, Data)

{-|
  Convert an 'AuthResponse' into a 'UcamWebauthInfo' for export.

  This should not be exported. Instead export 'getAuthInfo'
-}
extractAuthInfo :: Alternative f => AuthResponse a -> f (UcamWebauthInfo a)
extractAuthInfo AuthResponse{..} = maybe empty pure $ do
        _approveUser <- _ucamAPrincipal
        return AuthInfo{..}
        where
            _approveUniq = (_ucamAIssue, _ucamAId)
            _approveAttribs = _ucamAPtags ?: empty
            _approveLife = _ucamALife
            _approveParams = _ucamAParams

------------------------------------------------------------------------------
-- *** Protocol version

{-|
  Intended to be used as values, but Kind promotion means they can be used as types.
-}
data WLSVersion
    = WLS1 -- ^ Version 1 of the protocol. In the Raven implementation, failures use this version
    | WLS2 -- ^ Version 2
    | WLS3 -- ^ Version 3. Used for successful reponses by the Raven implementation
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show WLSVersion where
    show = displayWLSVersion

{-|
  Used for 'Show' instance.
-}
displayWLSVersion :: IsString a => WLSVersion -> a
displayWLSVersion WLS1 = "1"
displayWLSVersion WLS2 = "2"
displayWLSVersion WLS3 = "3"

{-|
  Like the 'Show' instance, but typed to 'ByteString'.

-}
bsDisplayWLSVersion :: WLSVersion -> ByteString
bsDisplayWLSVersion = displayWLSVersion

------------------------------------------------------------------------------
-- *** Authentication types available

{-|
  An enumeration of valid authentication types. The protocol currently only defines one
  valid type.
-}
data AuthType
    = Pwd -- ^ pwd: Username and password
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show AuthType where
    show = displayAuthType

{-|
  Implement show generically
-}
displayAuthType :: IsString a => AuthType -> a
displayAuthType Pwd = "pwd"

------------------------------------------------------------------------------
-- *** Data possibly useful for authorization (ptags)

{-|
  This is only in protocol versions ≥ 3
-}
data Ptag
    = Current -- ^ User is current member of university
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show Ptag where
    show = displayPtag

{-|
  Generic 'Show' implementation
-}
displayPtag :: IsString a => Ptag -> a
displayPtag Current = "current"

instance ToJSON Ptag
instance FromJSON Ptag

------------------------------------------------------------------------------
-- *** HTTP response codes
{- $statusCodes
  A data type representing the HTTP status codes in the protocol. This is compatible
  with the 'Status' type, but using the algebraic data type makes working with it
  a little nicer.
-}

{-|
  The valid HTTP status codes, according to the protocol.

  'BadRequest400' is present as a default, if there is any other code received.
-}
data StatusCode
    = Ok200          -- ^ Authentication successful
    | Gone410        -- ^ Cancelled by the user
    | NoAuth510      -- ^ No mutually acceptable authentication types
    | ProtoErr520    -- ^ Unsupported protocol version (Only for version 1)
    | ParamErr530    -- ^ General request parameter error
    | NoInteract540  -- ^ Interaction would be required but has been blocked
    | UnAuthAgent560 -- ^ Application agent is not authorised
    | Declined570    -- ^ Authentication declined
    | BadRequest400  -- ^ Response not covered by any protocol responses
    deriving (Show, Read, Eq, Ord, Bounded, Generic, Typeable, Data)

instance Enum StatusCode where
    toEnum = fromMaybe BadRequest400 . flip IntMap.lookup responseCodes
    fromEnum = statusCode . getStatus

{-|
  An 'IntMap' of 'Status' code numbers in the protocol to their typed representations.
-}
responseCodes :: IntMap StatusCode
responseCodes = IntMap.fromList . fmap (statusCode . getStatus &&& id) $ [Ok200, Gone410, NoAuth510, ProtoErr520, ParamErr530, NoInteract540, UnAuthAgent560, Declined570]

{-|
  Convert to the 'Status' type, defaulting to 'badRequest400' for a bad request
-}
getStatus :: StatusCode -> Status
getStatus Ok200 = ok200
getStatus Gone410 = gone410
getStatus NoAuth510 = noAuth510
getStatus ProtoErr520 = protoErr520
getStatus ParamErr530 = paramErr530
getStatus NoInteract540 = noInteract540
getStatus UnAuthAgent560 = unAuthAgent560
getStatus Declined570 = declined570
getStatus _ = badRequest400

------------------------------------------------------------------------------
-- *** 'Status' values

noAuth510, protoErr520, paramErr530, noInteract540, unAuthAgent560, declined570 :: Status
noAuth510      = mkStatus 510 "No mutually acceptable authentication types"
protoErr520    = mkStatus 520 "Unsupported protocol version (Only for version 1)"
paramErr530    = mkStatus 530 "General request parameter error"
noInteract540  = mkStatus 540 "Interaction would be required but has been blocked"
unAuthAgent560 = mkStatus 560 "Application agent is not authorised"
declined570    = mkStatus 570 "Authentication declined"

------------------------------------------------------------------------------
-- *** iact yes or no

{-|
  This is like a Boolean, but specifically for the ‘iact’ parameter
-}
data YesNo
    = No
    | Yes
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show YesNo where
    show = displayYesNo

displayYesNo :: IsString a => YesNo -> a
displayYesNo Yes = "yes"
displayYesNo _ = "no"

{-|
  Monomorphic variant of 'displayYesNo'
-}
bsDisplayYesNo :: YesNo -> ByteString
bsDisplayYesNo = displayYesNo

------------------------------------------------------------------------------
-- *** fail yes

{-|
  Like '()' but specifically for the ‘iact’ parameter
-}
newtype YesOnly = YesOnly' ()
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

pattern YesOnly :: YesOnly
pattern YesOnly = YesOnly' ()

{-# COMPLETE YesOnly #-}

instance Show YesOnly where
    show = displayYesOnly

displayYesOnly :: IsString a => YesOnly -> a
displayYesOnly YesOnly = "yes"

{-|
  Monomorphic variant of 'displayYesOnly'
-}
bsDisplayYesOnly :: YesOnly -> ByteString
bsDisplayYesOnly = displayYesOnly

------------------------------------------------------------------------------
-- *** Keys

{-|
  The key id, representing the public key for the @WLS@, is composed of a subset of 'ByteString' identifiers

  Do not export constructors
-}
newtype KeyID = KeyID { unKeyID :: ByteString }
    deriving (Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

instance Show KeyID where
    show = B.unpack . unKeyID

------------------------------------------------------------------------------
-- *** Time

{-|
  The modified UTCTime representation used in the protocol, based on RFC 3339. All
  time zones are 'utc'.

  Do not export constructor or accessor.
-}
newtype UcamTime = UcamTime { unUcamTime :: Text }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  'DiffTime' with 'ToJSON' and 'FromJSON' instances.
-}
newtype TimePeriod = TimePeriod { timePeriod :: DiffTime }
    deriving (Show, Eq, Ord, Num, Generic, Typeable, Data)

secondsFromTimePeriod :: TimePeriod -> Integer
secondsFromTimePeriod = (`div` 1e12) . diffTimeToPicoseconds . timePeriod

timePeriodFromSeconds :: Integer -> TimePeriod
timePeriodFromSeconds = TimePeriod . secondsToDiffTime

instance ToJSON TimePeriod where
    toJSON = toJSON . secondsFromTimePeriod
    toEncoding = toEncoding . secondsFromTimePeriod
instance FromJSON TimePeriod where
    parseJSON = withObject "Seconds" $ \v -> timePeriodFromSeconds
        <$> v .: "Seconds"

------------------------------------------------------------------------------
-- * 'WAASettings' and lenses

{-|
  The state involved in authentication. This includes the settings as 'WAASettings' and 
  the request as 'AuthRequest'.

  Do not export constructors or accessors, only lenses.
-}
data WAAState a = MakeWAAState
    { _wSet :: WAASettings
    , _aReq :: AuthRequest a
    --, _aSrs :: SignedAuthResponse valid a
    } deriving (Show, Eq, Ord, Generic, Typeable, Data)

{-|
  The settings for the application.

  Do not export constructors or accessors, only lenses.
  TODO Make urls type safe
-}
data WAASettings = MakeWAASettings
    { _authAccepted :: [AuthType]
    , _needReauthentication :: Maybe YesNo
    , _syncTimeOut :: NominalDiffTime
    , _validKids :: [KeyID]
    , _recentTime :: UTCTime
    , _applicationUrl :: Text
    , _wlsUrl :: Text
    } deriving (Show, Eq, Ord, Generic, Typeable, Data)

{-|
  Type synonym for WAASettings settings type.
-}
type SetWAA a = State (WAAState a) ()

{-|
  The default @WAA@ settings. To accept the defaults, use

  > configWAA def

  or

  > configWAA . return $ ()

  To modify settings, use the provided lenses.

  'configWAA' should not be exported. Instead, all functions requiring settings
  should use this function in a view pattern.
-}
configWAA :: SetWAA a -> WAAState a
configWAA = flip execState MakeWAAState
        { _wSet = settings
        , _aReq = request
        }

    where
        settings :: WAASettings
        settings = MakeWAASettings
            { _authAccepted = [Pwd]
            , _needReauthentication = Nothing
            , _syncTimeOut = 40
            , _validKids = empty
            , _recentTime = error "You must assign a time to check the issue time of a response is valid."
            , _applicationUrl = mempty
            , _wlsUrl = error "You must enter a URL for the authentication server."
            }

        request :: AuthRequest a
        request = MakeAuthRequest
            { _ucamQVer = WLS3
            , _ucamQUrl = error "You must enter a URL for the application wishing to authenticate the user."
            , _ucamQDesc = pure "This should be the ASCII description of the application requesting authentication"
            , _ucamQAauth = empty
            , _ucamQIact = empty
            , _ucamQMsg = pure "This should be the reason authentication is requested."
            , _ucamQParams = empty
            , _ucamQDate = empty
            , _ucamQFail = pure YesOnly
            }

------------------------------------------------------------------------------
-- * Text encoding

{-|
  Ensure Base 64 URL text is not confused with other 'ByteString's
-}
newtype Base64UBS = B64U { unB64U :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

instance FromJSON Base64UBS where
    parseJSON = withObject "Base 64 URL ByteString" $ \v -> B64U . encodeUtf8
        <$> v .: "Base 64U ByteString"

instance ToJSON Base64UBS where
    toJSON = toJSON . decodeUtf8 . unB64U
    toEncoding = toEncoding . decodeUtf8 . unB64U

newtype Base64UBSL = B64UL { unB64UL :: BSL.ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

instance FromJSON Base64UBSL where
    parseJSON = withObject "Base 64 URL ByteString" $ \v -> B64UL . TL.encodeUtf8
        <$> v .: "Base 64U ByteString"

instance ToJSON Base64UBSL where
    toJSON = toJSON . TL.decodeUtf8 . unB64UL
    toEncoding = toEncoding . TL.decodeUtf8 . unB64UL

{-|
  Ensure Base 64 URL text modified to fit the Ucam-Webauth protocol is not confused with other 'ByteString's
-}
newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

newtype UcamBase64BSL = UcamB64L { unUcamB64L :: BSL.ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Ensure ASCII text is not confused with other 'ByteString's
-}
newtype ASCII = ASCII { unASCII :: Text }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)
