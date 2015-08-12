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
import Control.Applicative (empty, Alternative)
import Network.Protocol.UcamWebauth.Internal

import Data.Data
import GHC.Generics

-- Settings
import Data.Lens.Internal

-- Character encoding
import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import Data.Char (isAlphaNum)

-- Time
import Data.Time.RFC3339
import Data.Time.LocalTime
import Data.Time (DiffTime, NominalDiffTime)

-- HTTP protocol
import Network.HTTP.Types

-- Map structures
import qualified Data.IntMap.Strict as I

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
                  approveUniq :: (UTCTime, Text) -- ^ Unique representation of response, composed of issue and id
                , approveUser :: Text -- ^ Identity of authenticated user
                , approveAttribs :: [Ptag] -- ^ Comma separated attributes of user
                , approveLife :: Maybe DiffTime -- ^ Remaining lifetime in seconds of application
                , approveParams :: Maybe a -- ^ A copy of the params from the request
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

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
                  ucamQVer :: WLSVersion -- ^ The version of @WLS.@ 1, 2 or 3.
                , ucamQUrl :: Text -- ^ Full http(s) url of resource request for display, and redirection after authentication at the @WLS@
                , ucamQDesc :: Maybe Text -- ^ Description, transmitted as ASCII
                , ucamQAauth :: Maybe [AuthType] -- ^ Comma delimited sequence of text tokens representing satisfactory authentication methods
                , ucamQIact :: Maybe Bool -- ^ A token (Yes/No). Yes requires re-authentication. No requires no interaction.
                , ucamQMsg :: Maybe Text -- ^ Why is authentication being requested?
                , ucamQParams :: Maybe a -- ^ Data to be returned to the application
                , ucamQDate :: Maybe UTCTime -- ^ RFC 3339 representation of application’s time
                , ucamQFail :: Maybe Bool -- ^ Error token. If 'yes', the @WLS@ implements error handling
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  A 'SignedAuthResponse' represents the data returned by the @WLS@, including a
  representation of the content returned (in the 'AuthResponse' data type), and
  the cryptographic signature, for verification.

  The phantom parameter 'valid' corr
-}
data SignedAuthResponse (valid :: IsValid) a = SignedAuthResponse {
                  ucamAResponse :: AuthResponse a -- ^ The bit of the response that is signed
                , ucamAToSign :: ByteString -- ^ The raw text of the response, used to verify the signature
                , ucamAKid :: Maybe KeyID -- ^ RSA key identifier. Must be a string of 1–8 characters, chosen from digits 0–9, with no leading 0, i.e. [1-9][0-9]{0,7}
                , ucamASig :: Maybe UcamBase64BS -- ^ Required if status is 200, otherwise Nothing. Public key signature of everything up to kid, using the private key identified by kid, the SHA-1 algorithm and RSASSA-PKCS1-v1_5 (PKCS #1 v2.1 RFC 3447), encoded using the base64 scheme (RFC 1521) but with "-._" replacing "+/="
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

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
                  ucamAVer :: WLSVersion -- ^ The version of @WLS@: 1, 2 or 3
                , ucamAStatus :: StatusCode -- ^ 3 digit status code (200 is success)
                , ucamAMsg :: Maybe Text -- ^ The status, for users
                , ucamAIssue :: UTCTime -- ^ RFC 3339 representation of response’s time
                , ucamAId :: Text -- ^ Not unguessable identifier, id + issue are unique
                , ucamAUrl :: Text -- ^ Same as request
                , ucamAPrincipal :: Maybe Text -- ^ Identity of authenticated user. Must be present if ucamAStatus is 200, otherwise must be Nothing
                , ucamAPtags :: Maybe [Ptag] -- ^ Comma separated attributes of principal. Optional in version 3, must be Nothing otherwise.
                , ucamAAuth :: Maybe AuthType -- ^ Authentication type if successful, else Nothing
                , ucamASso :: Maybe [AuthType] -- ^ Comma separated list of previous authentications. Required if ucamAAuth is Nothing.
                , ucamALife :: Maybe DiffTime -- ^ Remaining lifetime in seconds of application
                , ucamAParams :: Maybe a -- ^ A copy of the params from the request
                }
    deriving (Show, Eq, Ord, Generic1, Typeable, Data)

{-|
  Takes a validated 'SignedAuthResponse', and returns the corresponding 'UcamWebauthInfo'.
-}
getAuthInfo :: Alternative f => SignedAuthResponse 'Valid a -> f (UcamWebauthInfo a)
getAuthInfo = extractAuthInfo . ucamAResponse

{-|
  Convert an 'AuthResponse' into a 'UcamWebauthInfo' for export.

  TODO This should not be exported. Instead export 'getAuthInfo'
-}
extractAuthInfo :: Alternative f => AuthResponse a -> f (UcamWebauthInfo a)
extractAuthInfo AuthResponse{..} = liftMaybe $ do
        approveUser <- ucamAPrincipal
        return AuthInfo{..}
        where
            approveUniq = (ucamAIssue, ucamAId)
            approveAttribs = fromMaybe empty ucamAPtags
            approveLife = ucamALife
            approveParams = ucamAParams

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
responseCodes = I.fromList . fmap (statusCode . getStatus &&& id) $ [Ok200, Gone410, NoAuth510, ProtoErr520, ParamErr530, NoInteract540, UnAuthAgent560, Declined570]

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
                 , _needReauthentication :: Maybe Bool
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
authAccepted :: Lens' WAASettings [AuthType]
authAccepted f WAASettings{..} = (\_authAccepted -> WAASettings{_authAccepted, ..}) <$> f _authAccepted

{-|
  'Just' 'True' means ‘must reauthenticate’, 'Just' 'False' means ‘non-interactive’, 'Nothing' means anything goes.

  Default 'Nothing'
-}
needReauthentication :: Lens' WAASettings (Maybe Bool)
needReauthentication f WAASettings{..} = (\_needReauthentication -> WAASettings{_needReauthentication, ..}) <$> f _needReauthentication

{-|
  A timeout for the response validation.

  Default @40@ (seconds)
-}
syncTimeOut :: Lens' WAASettings NominalDiffTime
syncTimeOut f WAASettings{..} = (\_syncTimeOut -> WAASettings{_syncTimeOut, ..}) <$> f _syncTimeOut

{-|
  Valid 'KeyID' values for the protocol.

  Default @[]@ (/i.e./ no valid keys)
-}
validKids :: Lens' WAASettings [KeyID]
validKids f WAASettings{..} = (\_validKids -> WAASettings{_validKids, ..}) <$> f _validKids

{-|
  The last time something interesting happened. With an interesting definition of interesting.

  Default is the start of 'UTCTime'.

  TODO Document when this is updated, here.
-}
recentTime :: Lens' WAASettings UTCTime
recentTime f WAASettings{..} = (\_recentTime -> WAASettings{_recentTime, ..}) <$> f _recentTime

{-|
  The url to be transmitted to the @WLS@ is the url to which it redirects the 
  user’s browser after the submission, and the url which it displays to the user
  (in the case of Raven).

  Default is empty. The implementation __must__ override it.
-}
applicationUrl :: Lens' WAASettings Text
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
newtype ASCII = ASCII { unASCII :: ByteString }
    deriving (Show, Read, Eq, Ord, Semigroup, Monoid, IsString, Generic, Typeable, Data)

