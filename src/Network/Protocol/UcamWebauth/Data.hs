{-# OPTIONS_HADDOCK hide, not_here #-}

{-|
Module      : Network.Protocol.UcamWebauth.Data
Description : Data types used in Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Data (
    module Network.Protocol.UcamWebauth.Data
)   where

-- Prelude
import ClassyPrelude

import Network.Protocol.UcamWebauth.Internal

import Data.Data
import GHC.Generics

-- Settings
import Data.Lens.Internal

-- Character encoding
import qualified Data.ByteString.Base64 as B

import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import Data.Char (isAlphaNum, isAscii)

-- Time
import Data.Time.RFC3339
import Data.Time.LocalTime
import Data.Time (DiffTime, NominalDiffTime)

-- HTTP protocol
import Network.HTTP.Types

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
                , _approveLife :: Maybe DiffTime
                , _approveParams :: Maybe a
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  Unique representation of response, composed of issue and id
-}
approveUniq :: UcamWebauthInfo a :~> (UTCTime, Text)
approveUniq f AuthInfo{..} = (\_approveUniq -> AuthInfo{_approveUniq, ..}) <$> f _approveUniq

{-|
  Identity of authenticated user
-}
approveUser :: UcamWebauthInfo a :~> Text
approveUser f AuthInfo{..} = (\_approveUser -> AuthInfo{_approveUser, ..}) <$> f _approveUser

{-|
  Comma separated attributes of user
-}
approveAttribs :: UcamWebauthInfo a :~> [Ptag]
approveAttribs f AuthInfo{..} = (\_approveAttribs -> AuthInfo{_approveAttribs, ..}) <$> f _approveAttribs

{-|
  Remaining lifetime in seconds of application
-}
approveLife :: UcamWebauthInfo a :~> Maybe DiffTime
approveLife f AuthInfo{..} = (\_approveLife -> AuthInfo{_approveLife, ..}) <$> f _approveLife

{-|
  A copy of the params from the request
-}
approveParams :: UcamWebauthInfo a :~> Maybe a
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
data AuthRequest a = AuthRequest {
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
ucamQVer :: AuthRequest a :~> WLSVersion
ucamQVer f AuthRequest{..} = (\_ucamQVer -> AuthRequest{_ucamQVer, ..}) <$> f _ucamQVer

{-|
  Full http(s) url of resource request for display, and redirection after authentication at the @WLS@
-}
ucamQUrl :: AuthRequest a :~> Text
ucamQUrl f AuthRequest{..} = (\_ucamQUrl -> AuthRequest{_ucamQUrl, ..}) <$> f _ucamQUrl

{-|
  Description, transmitted as ASCII
-}
ucamQDesc :: AuthRequest a :~> Maybe ASCII
ucamQDesc f AuthRequest{..} = (\_ucamQDesc -> AuthRequest{_ucamQDesc, ..}) <$> f _ucamQDesc

{-|
  Comma delimited sequence of text tokens representing satisfactory authentication methods
-}
ucamQAauth :: AuthRequest a :~> Maybe [AuthType]
ucamQAauth f AuthRequest{..} = (\_ucamQAauth -> AuthRequest{_ucamQAauth, ..}) <$> f _ucamQAauth

{-|
  A token (Yes/No). Yes requires re-authentication. No requires no interaction.
-}
ucamQIact :: AuthRequest a :~> Maybe YesNo
ucamQIact f AuthRequest{..} = (\_ucamQIact -> AuthRequest{_ucamQIact, ..}) <$> f _ucamQIact

{-|
  Why is authentication being requested?
-}
ucamQMsg :: AuthRequest a :~> Maybe Text
ucamQMsg f AuthRequest{..} = (\_ucamQMsg -> AuthRequest{_ucamQMsg, ..}) <$> f _ucamQMsg

{-|
  Data to be returned to the application
-}
ucamQParams :: AuthRequest a :~> Maybe a
ucamQParams f AuthRequest{..} = (\_ucamQParams -> AuthRequest{_ucamQParams, ..}) <$> f _ucamQParams

{-|
  RFC 3339 representation of application’s time
-}
ucamQDate :: AuthRequest a :~> Maybe UTCTime
ucamQDate f AuthRequest{..} = (\_ucamQDate -> AuthRequest{_ucamQDate, ..}) <$> f _ucamQDate

{-|
  Error token. If 'yes', the @WLS@ implements error handling
-}
ucamQFail :: AuthRequest a :~> Maybe YesOnly
ucamQFail f AuthRequest{..} = (\_ucamQFail -> AuthRequest{_ucamQFail, ..}) <$> f _ucamQFail

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
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  The bit of the response that is signed
-}
ucamAResponse :: SignedAuthResponse valid a :~> AuthResponse a
ucamAResponse f SignedAuthResponse{..} = (\_ucamAResponse -> SignedAuthResponse{_ucamAResponse, ..}) <$> f _ucamAResponse

{-|
  The raw text of the response, used to verify the signature
-}
ucamAToSign :: SignedAuthResponse valid a :~> ByteString
ucamAToSign f SignedAuthResponse{..} = (\_ucamAToSign -> SignedAuthResponse{_ucamAToSign, ..}) <$> f _ucamAToSign

{-|
  RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
-}
ucamAKid :: SignedAuthResponse valid a :~> Maybe KeyID
ucamAKid f SignedAuthResponse{..} = (\_ucamAKid -> SignedAuthResponse{_ucamAKid, ..}) <$> f _ucamAKid

{-|
  Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/="
-}
ucamASig :: SignedAuthResponse valid a :~> Maybe UcamBase64BS
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
                , _ucamALife :: Maybe DiffTime
                , _ucamAParams :: Maybe a
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  The version of @WLS@: 1, 2 or 3
-}
ucamAVer :: AuthResponse a :~> WLSVersion
ucamAVer f AuthResponse{..} = (\_ucamAVer -> AuthResponse{_ucamAVer, ..}) <$> f _ucamAVer

{-|
  3 digit status code (200 is success)
-}
ucamAStatus :: AuthResponse a :~> StatusCode
ucamAStatus f AuthResponse{..} = (\_ucamAStatus -> AuthResponse{_ucamAStatus, ..}) <$> f _ucamAStatus

{-|
  The status, for users
-}
ucamAMsg :: AuthResponse a :~> Maybe Text
ucamAMsg f AuthResponse{..} = (\_ucamAMsg -> AuthResponse{_ucamAMsg, ..}) <$> f _ucamAMsg

{-|
  RFC 3339 representation of response’s time
-}
ucamAIssue :: AuthResponse a :~> UTCTime
ucamAIssue f AuthResponse{..} = (\_ucamAIssue -> AuthResponse{_ucamAIssue, ..}) <$> f _ucamAIssue

{-|
  Not unguessable identifier, id + issue are unique
-}
ucamAId :: AuthResponse a :~> Text
ucamAId f AuthResponse{..} = (\_ucamAId -> AuthResponse{_ucamAId, ..}) <$> f _ucamAId

{-|
  Same as request
-}
ucamAUrl :: AuthResponse a :~> Text
ucamAUrl f AuthResponse{..} = (\_ucamAUrl -> AuthResponse{_ucamAUrl, ..}) <$> f _ucamAUrl

{-|
  Identity of authenticated user. Must be present if ucamAStatus is 200, otherwise must be Nothing
-}
ucamAPrincipal :: AuthResponse a :~> Maybe Text
ucamAPrincipal f AuthResponse{..} = (\_ucamAPrincipal -> AuthResponse{_ucamAPrincipal, ..}) <$> f _ucamAPrincipal

{-|
  Comma separated attributes of principal. Optional in version 3, must be Nothing otherwise.
-}
ucamAPtags :: AuthResponse a :~> Maybe [Ptag]
ucamAPtags f AuthResponse{..} = (\_ucamAPtags -> AuthResponse{_ucamAPtags, ..}) <$> f _ucamAPtags

{-|
  Authentication type if successful, else Nothing
-}
ucamAAuth :: AuthResponse a :~> Maybe AuthType
ucamAAuth f AuthResponse{..} = (\_ucamAAuth -> AuthResponse{_ucamAAuth, ..}) <$> f _ucamAAuth

{-|
  Comma separated list of previous authentications. Required if ucamAAuth is Nothing.
-}
ucamASso :: AuthResponse a :~> Maybe [AuthType]
ucamASso f AuthResponse{..} = (\_ucamASso -> AuthResponse{_ucamASso, ..}) <$> f _ucamASso

{-|
  Remaining lifetime in seconds of application
-}
ucamALife :: AuthResponse a :~> Maybe DiffTime
ucamALife f AuthResponse{..} = (\_ucamALife -> AuthResponse{_ucamALife, ..}) <$> f _ucamALife

{-|
  A copy of the params from the request
-}
ucamAParams :: AuthResponse a :~> Maybe a
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
            _approveAttribs = fromMaybe empty _ucamAPtags
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
    toEnum = fromMaybe BadRequest400 . flip lookup responseCodes
    fromEnum = statusCode . getStatus

{-|
  An 'IntMap' of 'Status' code numbers in the protocol to their typed representations.
-}
responseCodes :: IntMap StatusCode
responseCodes = mapFromList . fmap (statusCode . getStatus &&& id) $ [Ok200, Gone410, NoAuth510, ProtoErr520, ParamErr530, NoInteract540, UnAuthAgent560, Declined570]

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

------------------------------------------------------------------------------
-- * 'WAASettings' and lenses

{-|
  The settings for the application.

  TODO Do not export constructors or accessors, only lenses.
-}
data WAASettings = WAASettings {
                   _authAccepted :: [AuthType]
                 , _needReauthentication :: Maybe YesNo
                 , _syncTimeOut :: NominalDiffTime
                 , _validKids :: [KeyID]
                 , _recentTime :: UTCTime
                 , _applicationUrl :: Text
                 }
                 deriving (Show, Eq, Ord, Generic, Typeable, Data)

{-|
  Accepted authentication types by the protocol.

  Default @['Pwd']@
-}
authAccepted :: WAASettings :~> [AuthType]
authAccepted f WAASettings{..} = (\_authAccepted -> WAASettings{_authAccepted, ..}) <$> f _authAccepted

{-|
  'Just' 'True' means ‘must reauthenticate’, 'Just' 'False' means ‘non-interactive’, 'Nothing' means anything goes.

  Default 'Nothing'
-}
needReauthentication :: WAASettings :~> Maybe YesNo
needReauthentication f WAASettings{..} = (\_needReauthentication -> WAASettings{_needReauthentication, ..}) <$> f _needReauthentication

{-|
  A timeout for the response validation.

  Default @40@ (seconds)
-}
syncTimeOut :: WAASettings :~> NominalDiffTime
syncTimeOut f WAASettings{..} = (\_syncTimeOut -> WAASettings{_syncTimeOut, ..}) <$> f _syncTimeOut

{-|
  Valid 'KeyID' values for the protocol.

  Default @[]@ (/i.e./ no valid keys)
-}
validKids :: WAASettings :~> [KeyID]
validKids f WAASettings{..} = (\_validKids -> WAASettings{_validKids, ..}) <$> f _validKids

{-|
  The last time something interesting happened. With an interesting definition of interesting.

  Default is the start of 'UTCTime'.

  TODO Document when this is updated, here.
-}
recentTime :: WAASettings :~> UTCTime
recentTime f WAASettings{..} = (\_recentTime -> WAASettings{_recentTime, ..}) <$> f _recentTime

{-|
  The url to be transmitted to the @WLS@ is the url to which it redirects the 
  user’s browser after the submission, and the url which it displays to the user
  (in the case of Raven).

  Default is empty. The implementation __must__ override it.
-}
applicationUrl :: WAASettings :~> Text
applicationUrl f WAASettings{..} = (\_applicationUrl -> WAASettings{_applicationUrl, ..}) <$> f _applicationUrl

------------------------------------------------------------------------------
-- * Text encoding

{-|
  Ensure Base 64 text is not confused with other 'ByteString's
-}
newtype Base64BS = B64 { unB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Ensure Base 64 text modified to fit the Ucam-Webauth protocol is not confused with other 'ByteString's
-}
newtype UcamBase64BS = UcamB64 { unUcamB64 :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Ensure ASCII text is not confused with other 'ByteString's
-}
newtype ASCII = ASCII { unASCII :: Text }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

{-|
  Convert to the protocol’s version of base64
-}
convertB64Ucam :: Base64BS -> UcamBase64BS
convertB64Ucam = UcamB64 . B.map camFilter . unB64
    where
        camFilter :: Char -> Char
        camFilter '+' = '-'
        camFilter '/' = '.'
        camFilter '=' = '_'
        camFilter x = x

{-|
  Convert from the protocol’s version of base64
-}
convertUcamB64 :: UcamBase64BS -> Base64BS
convertUcamB64 = B64 . B.map camFilter . unUcamB64
    where
        camFilter :: Char -> Char
        camFilter '-' = '+'
        camFilter '.' = '/'
        camFilter '_' = '='
        camFilter x = x

{-|
  This uses 'B.decodeLenient' internally.

  TODO It should not be a problem, if operating on validated input, but might be worth testing (low priority).
-}
decodeUcamB64 :: UcamBase64BS -> StringType
decodeUcamB64 = B.decodeLenient . unB64 . convertUcamB64

{-|
  Unlike decoding, this is fully pure.
-}
encodeUcamB64 :: StringType -> UcamBase64BS
encodeUcamB64 = convertB64Ucam . B64 . B.encode

{-|
  Extract ascii text.

  TODO Use Haskell’s utf7 functions
-}
decodeASCII :: ASCII -> Text
decodeASCII = filter isAscii . unASCII
