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

{-|
Module      : Network.Protocol.UcamWebauth.Data
Description : Data types used in Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Data (
    module Network.Protocol.UcamWebauth.Data
)   where

-- Prelude
import Network.Protocol.UcamWebauth.Internal

import "base" Data.Data
import "base" GHC.Generics
import "base" Control.Applicative
import "base" Data.String
import "base" Data.Semigroup
import "containers" Data.IntMap (IntMap)
import qualified "containers" Data.IntMap as IntMap
import "errors" Control.Error
import "base" Control.Arrow ((&&&))

-- Settings
import "microlens" Lens.Micro

-- Character encoding
import qualified "base64-bytestring" Data.ByteString.Base64.URL as B
import qualified "base64-bytestring" Data.ByteString.Base64.URL.Lazy as BL

import "bytestring" Data.ByteString (ByteString)
import qualified "bytestring" Data.ByteString.Char8 as B
import qualified "bytestring" Data.ByteString.Lazy.Char8 as BL
import qualified "bytestring" Data.ByteString.Lazy as BSL
import "text" Data.Text (Text)
import "text" Data.Text.Encoding
import qualified "text" Data.Text as T
import qualified "text" Data.Text.Lazy.Encoding as TL
import "base" Data.Char (isAlphaNum, isAscii)

import "aeson" Data.Aeson.Types

-- Time
import "timerep" Data.Time.RFC3339
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
data UcamWebauthInfo a = AuthInfo {
                  _approveUniq :: (UTCTime, Text)
                , _approveUser :: Text
                , _approveAttribs :: [Ptag]
                , _approveLife :: Maybe TimePeriod
                , _approveParams :: Maybe a
                }
    deriving (Show, Eq, Ord, Generic, Generic1, Typeable, Data)

instance ToJSON a => ToJSON (UcamWebauthInfo a)
instance FromJSON a => FromJSON (UcamWebauthInfo a)


{-|
  Unique representation of response, composed of issue and id
-}
approveUniq :: UcamWebauthInfo a `Lens'` (UTCTime, Text)
approveUniq f AuthInfo{..} = (\_approveUniq -> AuthInfo{_approveUniq, ..}) <$> f _approveUniq

{-|
  Identity of authenticated user
-}
approveUser :: UcamWebauthInfo a `Lens'` Text
approveUser f AuthInfo{..} = (\_approveUser -> AuthInfo{_approveUser, ..}) <$> f _approveUser

{-|
  Comma separated attributes of user
-}
approveAttribs :: UcamWebauthInfo a `Lens'` [Ptag]
approveAttribs f AuthInfo{..} = (\_approveAttribs -> AuthInfo{_approveAttribs, ..}) <$> f _approveAttribs

{-|
  Remaining lifetime in seconds of application
-}
approveLife :: UcamWebauthInfo a `Lens'` Maybe TimePeriod
approveLife f AuthInfo{..} = (\_approveLife -> AuthInfo{_approveLife, ..}) <$> f _approveLife

{-|
  A copy of the params from the request
-}
approveParams :: UcamWebauthInfo a `Lens'` Maybe a
approveParams f AuthInfo{..} = (\_approveParams -> AuthInfo{_approveParams, ..}) <$> f _approveParams

------------------------------------------------------------------------------
-- ** Type Synonyms

{-|
  A synonym to abstract much behaviour over a generic string type.
-}
type StringType = ByteString

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
data AuthRequest a = MakeAuthRequest {
                  _ucamQVer :: WLSVersion
                , _ucamQUrl :: Text
                , _ucamQDesc :: Maybe ASCII
                , _ucamQAauth :: Maybe [AuthType]
                , _ucamQIact :: Maybe YesNo
                , _ucamQMsg :: Maybe Text
                , _ucamQParams :: Maybe a
                , _ucamQDate :: Maybe UTCTime
                , _ucamQFail :: Maybe YesOnly
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  The version of @WLS.@ 1, 2 or 3.
-}
ucamQVer :: AuthRequest a `Lens'` WLSVersion
ucamQVer f MakeAuthRequest{..} = (\_ucamQVer -> MakeAuthRequest{_ucamQVer, ..}) <$> f _ucamQVer

{-|
  Full http(s) url of resource request for display, and redirection after authentication at the @WLS@

  TODO __This is required__
-}
ucamQUrl :: AuthRequest a `Lens'` Text
ucamQUrl f MakeAuthRequest{..} = (\_ucamQUrl -> MakeAuthRequest{_ucamQUrl, ..}) <$> f _ucamQUrl

{-|
  Description, transmitted as ASCII
-}
ucamQDesc :: AuthRequest a `Lens'` Maybe ASCII
ucamQDesc f MakeAuthRequest{..} = (\_ucamQDesc -> MakeAuthRequest{_ucamQDesc, ..}) <$> f _ucamQDesc

{-|
  Comma delimited sequence of text tokens representing satisfactory authentication methods
-}
ucamQAauth :: AuthRequest a `Lens'` Maybe [AuthType]
ucamQAauth f MakeAuthRequest{..} = (\_ucamQAauth -> MakeAuthRequest{_ucamQAauth, ..}) <$> f _ucamQAauth

{-|
  A token (Yes/No). Yes requires re-authentication. No requires no interaction.
-}
ucamQIact :: AuthRequest a `Lens'` Maybe YesNo
ucamQIact f MakeAuthRequest{..} = (\_ucamQIact -> MakeAuthRequest{_ucamQIact, ..}) <$> f _ucamQIact

{-|
  Why is authentication being requested?
-}
ucamQMsg :: AuthRequest a `Lens'` Maybe Text
ucamQMsg f MakeAuthRequest{..} = (\_ucamQMsg -> MakeAuthRequest{_ucamQMsg, ..}) <$> f _ucamQMsg

{-|
  Data to be returned to the application
-}
ucamQParams :: AuthRequest a `Lens'` Maybe a
ucamQParams f MakeAuthRequest{..} = (\_ucamQParams -> MakeAuthRequest{_ucamQParams, ..}) <$> f _ucamQParams

{-|
  RFC 3339 representation of application’s time
-}
ucamQDate :: AuthRequest a `Lens'` Maybe UTCTime
ucamQDate f MakeAuthRequest{..} = (\_ucamQDate -> MakeAuthRequest{_ucamQDate, ..}) <$> f _ucamQDate

{-|
  Error token. If 'yes', the @WLS@ implements error handling
-}
ucamQFail :: AuthRequest a `Lens'` Maybe YesOnly
ucamQFail f MakeAuthRequest{..} = (\_ucamQFail -> MakeAuthRequest{_ucamQFail, ..}) <$> f _ucamQFail

{-|
  A 'SignedAuthResponse' represents the data returned by the @WLS@, including a
  representation of the content returned (in the 'AuthResponse' data type), and
  the cryptographic signature, for verification.

  The phantom parameter 'valid' corr
-}
data SignedAuthResponse (valid :: IsValid) a = SignedAuthResponse {
                  _ucamAResponse :: AuthResponse a
                , _ucamAToSign :: ByteString
                , _ucamAKid :: Maybe KeyID
                , _ucamASig :: Maybe UcamBase64BS
                }
    deriving (Show, Eq, Ord, Generic, Generic1, Typeable, Data)

{-|
  The bit of the response that is signed
-}
ucamAResponse :: SignedAuthResponse valid a `Lens'` AuthResponse a
ucamAResponse f SignedAuthResponse{..} = (\_ucamAResponse -> SignedAuthResponse{_ucamAResponse, ..}) <$> f _ucamAResponse

{-|
  The raw text of the response, used to verify the signature
-}
ucamAToSign :: SignedAuthResponse valid a `Lens'` ByteString
ucamAToSign f SignedAuthResponse{..} = (\_ucamAToSign -> SignedAuthResponse{_ucamAToSign, ..}) <$> f _ucamAToSign

{-|
  RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
-}
ucamAKid :: SignedAuthResponse valid a `Lens'` Maybe KeyID
ucamAKid f SignedAuthResponse{..} = (\_ucamAKid -> SignedAuthResponse{_ucamAKid, ..}) <$> f _ucamAKid

{-|
  Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/=" (equivalent to the RFC 4648 with "._" replacing "_=").
-}
ucamASig :: SignedAuthResponse valid a `Lens'` Maybe UcamBase64BS
ucamASig f SignedAuthResponse{..} = (\_ucamASig -> SignedAuthResponse{_ucamASig, ..}) <$> f _ucamASig

{-|
  The intended use of this is with 'IsValid' as a kind (requires the 'DataKinds' extension).
  The data constructors 'Valid' and 'MaybeValid' are now type constructors, which indicate the
  validity of a 'SignedAuthResponse'.

  TODO This is not exported.
-}
data IsValid = MaybeValid
             | Valid
             deriving (Show, Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

{-|
  An 'AuthResponse' represents the content returned by the @WLS@. The validation
  machinery in this module returns the required data as a 'UcamWebauthInfo' value.
-}
data AuthResponse a = AuthResponse {
                  _ucamAVer :: WLSVersion
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
                }
    deriving (Show, Eq, Ord, Generic, Generic1, Typeable, Data)

{-|
  The version of @WLS@: 1, 2 or 3
-}
ucamAVer :: AuthResponse a `Lens'` WLSVersion
ucamAVer f AuthResponse{..} = (\_ucamAVer -> AuthResponse{_ucamAVer, ..}) <$> f _ucamAVer

{-|
  3 digit status code (200 is success)
-}
ucamAStatus :: AuthResponse a `Lens'` StatusCode
ucamAStatus f AuthResponse{..} = (\_ucamAStatus -> AuthResponse{_ucamAStatus, ..}) <$> f _ucamAStatus

{-|
  The status, for users
-}
ucamAMsg :: AuthResponse a `Lens'` Maybe Text
ucamAMsg f AuthResponse{..} = (\_ucamAMsg -> AuthResponse{_ucamAMsg, ..}) <$> f _ucamAMsg

{-|
  RFC 3339 representation of response’s time
-}
ucamAIssue :: AuthResponse a `Lens'` UTCTime
ucamAIssue f AuthResponse{..} = (\_ucamAIssue -> AuthResponse{_ucamAIssue, ..}) <$> f _ucamAIssue

{-|
  Not unguessable identifier, id + issue are unique
-}
ucamAId :: AuthResponse a `Lens'` Text
ucamAId f AuthResponse{..} = (\_ucamAId -> AuthResponse{_ucamAId, ..}) <$> f _ucamAId

{-|
  Same as request
-}
ucamAUrl :: AuthResponse a `Lens'` Text
ucamAUrl f AuthResponse{..} = (\_ucamAUrl -> AuthResponse{_ucamAUrl, ..}) <$> f _ucamAUrl

{-|
  Identity of authenticated user. Must be present if ucamAStatus is 200, otherwise must be Nothing
-}
ucamAPrincipal :: AuthResponse a `Lens'` Maybe Text
ucamAPrincipal f AuthResponse{..} = (\_ucamAPrincipal -> AuthResponse{_ucamAPrincipal, ..}) <$> f _ucamAPrincipal

{-|
  Comma separated attributes of principal. Optional in version 3, must be Nothing otherwise.
-}
ucamAPtags :: AuthResponse a `Lens'` Maybe [Ptag]
ucamAPtags f AuthResponse{..} = (\_ucamAPtags -> AuthResponse{_ucamAPtags, ..}) <$> f _ucamAPtags

{-|
  Authentication type if successful, else Nothing
-}
ucamAAuth :: AuthResponse a `Lens'` Maybe AuthType
ucamAAuth f AuthResponse{..} = (\_ucamAAuth -> AuthResponse{_ucamAAuth, ..}) <$> f _ucamAAuth

{-|
  Comma separated list of previous authentications. Required if ucamAAuth is Nothing.
-}
ucamASso :: AuthResponse a `Lens'` Maybe [AuthType]
ucamASso f AuthResponse{..} = (\_ucamASso -> AuthResponse{_ucamASso, ..}) <$> f _ucamASso

{-|
  Remaining lifetime in seconds of application
-}
ucamALife :: AuthResponse a `Lens'` Maybe TimePeriod
ucamALife f AuthResponse{..} = (\_ucamALife -> AuthResponse{_ucamALife, ..}) <$> f _ucamALife

{-|
  A copy of the params from the request
-}
ucamAParams :: AuthResponse a `Lens'` Maybe a
ucamAParams f AuthResponse{..} = (\_ucamAParams -> AuthResponse{_ucamAParams, ..}) <$> f _ucamAParams

{-|
  Takes a validated 'SignedAuthResponse', and returns the corresponding 'UcamWebauthInfo'.
-}
getAuthInfo :: Alternative f => SignedAuthResponse 'Valid a -> f (UcamWebauthInfo a)
getAuthInfo = extractAuthInfo . _ucamAResponse

{-|
  Convert an 'AuthResponse' into a 'UcamWebauthInfo' for export.

  TODO This should not be exported. Instead export 'getAuthInfo'
-}
extractAuthInfo :: Alternative f => AuthResponse a -> f (UcamWebauthInfo a)
extractAuthInfo AuthResponse{..} = liftMaybe $ do
        _approveUser <- _ucamAPrincipal
        return AuthInfo{..}
        where
            _approveUniq = (_ucamAIssue, _ucamAId)
            _approveAttribs = _ucamAPtags ?: empty
            _approveLife = _ucamALife
            _approveParams = _ucamAParams

------------------------------------------------------------------------------
-- * Typed representations of protocol data
{- $typed
  These types represent data such as the protocol version ('WLSVersion') that is 
  inherently typed but has a string representation in the protocol
-}

------------------------------------------------------------------------------
-- *** Protocol version

{-|
  Intended to be used as values, but Kind promotion means they can be used as types.
-}
data WLSVersion = WLS1 -- ^ Version 1 of the protocol. In the Raven implementation, failures use this version
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
  Like the 'Show' instance, but typed to 'StringType'.
-}
textWLSVersion :: WLSVersion -> StringType
textWLSVersion = displayWLSVersion

------------------------------------------------------------------------------
-- *** Authentication types available

{-|
  An enumeration of valid authentication types. The protocol currently only defines one
  valid type.
-}
data AuthType = Pwd -- ^ pwd: Username and password
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
data Ptag = Current -- ^ User is current member of university
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
data StatusCode = Ok200 -- ^ Authentication successful
                | Gone410 -- ^ Cancelled by the user
                | NoAuth510 -- ^ No mutually acceptable authentication types        
                | ProtoErr520 -- ^ Unsupported protocol version (Only for version 1)  
                | ParamErr530 -- ^ General request parameter error                    
                | NoInteract540 -- ^ Interaction would be required but has been blocked 
                | UnAuthAgent560 -- ^ Application agent is not authorised                
                | Declined570 -- ^ Authentication declined                            
                | BadRequest400 -- ^ Response not covered by any protocol responses
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
-- *** iact yes or no

{-|
  This is like a Boolean, but specifically for the ‘iact’ parameter
-}
data YesNo = No
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
displayYesNoS :: YesNo -> StringType
displayYesNoS = displayYesNo

------------------------------------------------------------------------------
-- *** fail yes

{-|
  Like '()' but specifically for the ‘iact’ parameter
-}
data YesOnly = YesOnly
    deriving (Read, Eq, Ord, Enum, Bounded, Generic, Typeable, Data)

instance Show YesOnly where
    show = displayYesOnly

displayYesOnly :: IsString a => YesOnly -> a
displayYesOnly YesOnly = "yes"

{-|
  Monomorphic variant of 'displayYesOnly'
-}
displayYesOnlyS :: YesOnly -> StringType
displayYesOnlyS = displayYesOnly


------------------------------------------------------------------------------
-- *** 'Status' values

noAuth510, protoErr520, paramErr530, noInteract540, unAuthAgent560, declined570 :: Status
noAuth510 = mkStatus 510 "No mutually acceptable authentication types"
protoErr520 = mkStatus 520 "Unsupported protocol version (Only for version 1)"
paramErr530 = mkStatus 530 "General request parameter error"
noInteract540 = mkStatus 540 "Interaction would be required but has been blocked"
unAuthAgent560 = mkStatus 560 "Application agent is not authorised"
declined570 = mkStatus 570 "Authentication declined"

------------------------------------------------------------------------------
-- *** Keys

{-|
  The key id, representing the public key for the @WLS@, is composed of a subset of 'ByteString' identifiers

  TODO Do not export constructors
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

  TODO Do not export constructor or accessor.
-}
newtype UcamTime = UcamTime { unUcamTime :: Text }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Convert a 'UTCTime' to the protocol time representation, based on the 'utc' time zone.
-}
ucamTime :: UTCTime -> UcamTime
ucamTime = UcamTime . T.filter isAlphaNum . formatTimeRFC3339 . utcToZonedTime utc

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

  TODO Do not export constructors or accessors, only lenses.
-}
data WAAState a = MakeWAAState {
                  _wSet :: WAASettings
                , _aReq :: AuthRequest a
                --, _aSrs :: SignedAuthResponse valid a
                }
                deriving (Show, Eq, Ord, Generic, Typeable, Data)

wSet :: WAAState a `Lens'` WAASettings
wSet f MakeWAAState{..} = (\_wSet -> MakeWAAState{_wSet, ..}) <$> f _wSet

aReq :: WAAState a `Lens'` AuthRequest a
aReq f MakeWAAState{..} = (\_aReq -> MakeWAAState{_aReq, ..}) <$> f _aReq

--aSrs :: WAAState a `Lens'` SignedAuthResponse valid a
--aSrs f MakeWAAState{..} = (\_aSrs -> MakeWAAState{_aSrs, ..}) <$> f _aSrs

{-|
  The settings for the application.

  TODO Do not export constructors or accessors, only lenses.
  TODO Make urls type safe
-}
data WAASettings = MakeWAASettings {
                   _authAccepted :: [AuthType]
                 , _needReauthentication :: Maybe YesNo
                 , _syncTimeOut :: NominalDiffTime
                 , _validKids :: [KeyID]
                 , _recentTime :: UTCTime
                 , _applicationUrl :: Text
                 , _wlsUrl :: Text
                 }
                 deriving (Show, Eq, Ord, Generic, Typeable, Data)

{-|
  Accepted authentication types by the protocol.

  Default @['Pwd']@
-}
authAccepted :: WAASettings `Lens'` [AuthType]
authAccepted f MakeWAASettings{..} = (\_authAccepted -> MakeWAASettings{_authAccepted, ..}) <$> f _authAccepted

{-|
  'Just' 'True' means ‘must reauthenticate’, 'Just' 'False' means ‘non-interactive’, 'Nothing' means anything goes.

  Default 'Nothing'
-}
needReauthentication :: WAASettings `Lens'` Maybe YesNo
needReauthentication f MakeWAASettings{..} = (\_needReauthentication -> MakeWAASettings{_needReauthentication, ..}) <$> f _needReauthentication

{-|
  A timeout for the response validation.

  Default @40@ (seconds)
-}
syncTimeOut :: WAASettings `Lens'` NominalDiffTime
syncTimeOut f MakeWAASettings{..} = (\_syncTimeOut -> MakeWAASettings{_syncTimeOut, ..}) <$> f _syncTimeOut

{-|
  Valid 'KeyID' values for the protocol.

  Default @[]@ (/i.e./ no valid keys)
-}
validKids :: WAASettings `Lens'` [KeyID]
validKids f MakeWAASettings{..} = (\_validKids -> MakeWAASettings{_validKids, ..}) <$> f _validKids

{-|
  The last time something interesting happened. With an interesting definition of interesting.

  Default is the start of 'UTCTime'.

  TODO Document when this is updated, here.
-}
recentTime :: WAASettings `Lens'` UTCTime
recentTime f MakeWAASettings{..} = (\_recentTime -> MakeWAASettings{_recentTime, ..}) <$> f _recentTime

{-|
  The url to be transmitted to the @WLS@ is the url to which it redirects the 
  user’s browser after the submission, and the url which it displays to the user
  (in the case of Raven).

  Default is empty. The implementation __must__ override it.
-}
applicationUrl :: WAASettings `Lens'` Text
applicationUrl f MakeWAASettings{..} = (\_applicationUrl -> MakeWAASettings{_applicationUrl, ..}) <$> f _applicationUrl

{-|
  The url to be transmitted to the @WLS@ is the url to which it redirects the 
  user’s browser after the submission, and the url which it displays to the user
  (in the case of Raven).

  Default is empty. The implementation __must__ override it.
-}
wlsUrl :: WAASettings `Lens'` Text
wlsUrl f MakeWAASettings{..} = (\_wlsUrl -> MakeWAASettings{_wlsUrl, ..}) <$> f _wlsUrl

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

{-|
  Convert to the protocol’s version of base64
-}
convertB64Ucam :: Base64UBS -> UcamBase64BS
convertB64Ucam = UcamB64 . B.map camEncodeFilter . unB64U

convertB64UcamL :: Base64UBSL -> UcamBase64BSL
convertB64UcamL = UcamB64L . BL.map camEncodeFilter . unB64UL

camEncodeFilter :: Char -> Char
camEncodeFilter '_' = '.'
camEncodeFilter '=' = '_'
camEncodeFilter x = x

{-|
  Convert from the protocol’s version of base64
-}
convertUcamB64 :: UcamBase64BS -> Base64UBS
convertUcamB64 = B64U . B.map camDecodeFilter . unUcamB64

convertUcamB64L :: UcamBase64BSL -> Base64UBSL
convertUcamB64L = B64UL . BL.map camDecodeFilter . unUcamB64L

camDecodeFilter :: Char -> Char
camDecodeFilter '.' = '_'
camDecodeFilter '_' = '='
camDecodeFilter x = x

{-|
  This uses 'B.decodeLenient' internally.

  TODO It should not be a problem, if operating on validated input, but might be worth testing (low priority).
-}
decodeUcamB64 :: UcamBase64BS -> StringType
decodeUcamB64 = B.decodeLenient . unB64U . convertUcamB64

decodeUcamB64L :: UcamBase64BSL -> BSL.ByteString
decodeUcamB64L = BL.decodeLenient . unB64UL . convertUcamB64L

{-|
  Unlike decoding, this is fully pure.
-}
encodeUcamB64 :: StringType -> UcamBase64BS
encodeUcamB64 = convertB64Ucam . B64U . B.encode

encodeUcamB64L :: BSL.ByteString -> UcamBase64BSL
encodeUcamB64L = convertB64UcamL . B64UL . BL.encode

{-|
  Extract ascii text.

  TODO Use Haskell’s utf7 functions
-}
decodeASCII :: ASCII -> Text
decodeASCII = T.filter isAscii . unASCII
