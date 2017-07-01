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
Module      : Network.Protocol.UcamWebauth.Data
Description : Data types used in Ucam-Webauth protocol
Maintainer  : David Baynard <davidbaynard@gmail.com>

-}

module Network.Protocol.UcamWebauth.Data
  ( UcamWebauthInfo()
  , approveUniq
  , approveUser
  , approveAttribs
  , approveLife
  , approveParams

  -- $request
  , AuthRequest()
  , ucamQVer
  , ucamQUrl
  , ucamQDesc
  , ucamQAauth
  , ucamQIact
  , ucamQMsg
  , ucamQParams
  , ucamQDate
  , ucamQFail

  , SignedAuthResponse()
  , ucamAResponse
  , ucamAToSign
  , ucamAKid
  , ucamASig

  , AuthResponse()
  , ucamAVer
  , ucamAStatus
  , ucamAMsg
  , ucamAIssue
  , ucamAId
  , ucamAUrl
  , ucamAPrincipal
  , ucamAPtags
  , ucamAAuth
  , ucamASso
  , ucamALife
  , ucamAParams

  -- $typed
  , getAuthInfo

  , WLSVersion(..)
  , displayWLSVersion

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

  , YesOnly(YesOnly)
  , displayYesOnly

  , KeyID()

  , UcamTime()
  , zonedUcamTime
  , ucamTime
  , TimePeriod()
  , secondsFromTimePeriod
  , timePeriodFromSeconds

  , WAAState()
  , wSet
  , aReq

  , WAASettings()
  , SetWAA

  , authAccepted
  , needReauthentication
  , syncTimeOut
  , validKids
  , recentTime
  , applicationUrl
  , wlsUrl
  , importedKeys

  , Base64UBS()
  , Base64UBSL()
  , UcamBase64BS()
  , UcamBase64BSL()
  , ASCII()
  , convertB64Ucam
  , convertB64UcamL
  , convertUcamB64
  , convertUcamB64L
  , decodeUcamB64
  , decodeUcamB64L
  , encodeUcamB64
  , encodeUcamB64L
  , decodeASCII'

  -- Other
  , (&~)
  ) where

import Network.Protocol.UcamWebauth.Data.Internal

-- Prelude
import "base" Control.Applicative

-- Settings
import "microlens" Lens.Micro
import "mtl" Control.Monad.State

-- Character encoding
import qualified "base64-bytestring" Data.ByteString.Base64.URL as B
import qualified "base64-bytestring" Data.ByteString.Base64.URL.Lazy as BL

import "bytestring" Data.ByteString (ByteString)
import qualified "bytestring" Data.ByteString.Char8 as B
import qualified "bytestring" Data.ByteString.Lazy.Char8 as BL
import qualified "bytestring" Data.ByteString.Lazy as BSL
import "text" Data.Text (Text)
import qualified "text" Data.Text as T
import "base" Data.Char (isAlphaNum, isAscii)
import "containers" Data.Map.Strict (Map)

-- Time
import "timerep" Data.Time.RFC3339
import "time" Data.Time

(&~) :: s -> State s a -> s
(&~) = flip execState
infixl 1 &~
{-# INLINE (&~) #-}

------------------------------------------------------------------------------
-- * Lenses

------------------------------------------------------------------------------
-- ** 'UcamWebauthInfo'

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
-- ** 'AuthRequest'
{- $request
  The handshake between the @WLS@ and @WAA@ are represented using the 'AuthRequest'
  and 'SignedAuthResponse' data types. The 'AuthResponse' type represents the
  content of a 'SignedAuthResponse'. Constructors and accessors are not exported,
  and the 'AuthRequest' should be build using the smart constructors provided.
-}

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

--------------------------------------------------
-- ** 'SignedAuthResponse'
--------------------------------------------------

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

--------------------------------------------------
-- ** 'AuthResponse'
--------------------------------------------------

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

------------------------------------------------------------------------------
-- * Typed representations of protocol data
{- $typed
  These types represent data such as the protocol version ('WLSVersion') that is 
  inherently typed but has a string representation in the protocol
-}

------------------------------------------------------------------------------
-- *** Time

{-|
  Convert the protocol time representation to a 'UTCTime', based on the 'utc' time zone.
-}
zonedUcamTime :: UcamTime -> Maybe ZonedTime
zonedUcamTime = parseTimeRFC3339 . unUcamTime

{-|
  Convert a 'UTCTime' to the protocol time representation, based on the 'utc' time zone.
-}
ucamTime :: UTCTime -> UcamTime
ucamTime = UcamTime . T.filter isAlphaNum . formatTimeRFC3339 . utcToZonedTime utc

------------------------------------------------------------------------------
-- * 'WAASettings' and lenses

wSet :: WAAState a `Lens'` WAASettings
wSet f MakeWAAState{..} = (\_wSet -> MakeWAAState{_wSet, ..}) <$> f _wSet

aReq :: WAAState a `Lens'` AuthRequest a
aReq f MakeWAAState{..} = (\_aReq -> MakeWAAState{_aReq, ..}) <$> f _aReq

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

  TODO Default is empty. The implementation __must__ override it.
-}
applicationUrl :: WAASettings `Lens'` Text
applicationUrl f MakeWAASettings{..} = (\_applicationUrl -> MakeWAASettings{_applicationUrl, ..}) <$> f _applicationUrl

{-|
  The url to be transmitted to the @WLS@ is the url to which it redirects the 
  user’s browser after the submission, and the url which it displays to the user
  (in the case of Raven).

  TODO Default is empty. The implementation __must__ override it.
-}
wlsUrl :: WAASettings `Lens'` Text
wlsUrl f MakeWAASettings{..} = (\_wlsUrl -> MakeWAASettings{_wlsUrl, ..}) <$> f _wlsUrl

{-|
  Rather than acquiring the keys from a static directory, it is possible to supply
  the key data during compilation; these are stored in a map, here.

  Defaults to an empty map.
-}
importedKeys :: WAASettings `Lens'` Map KeyID ByteString
importedKeys f MakeWAASettings{..} = (\_importedKeys -> MakeWAASettings{_importedKeys, ..}) <$> f _importedKeys

------------------------------------------------------------------------------
-- * Text encoding

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
decodeUcamB64 :: UcamBase64BS -> ByteString
decodeUcamB64 = B.decodeLenient . unB64U . convertUcamB64

decodeUcamB64L :: UcamBase64BSL -> BSL.ByteString
decodeUcamB64L = BL.decodeLenient . unB64UL . convertUcamB64L

{-|
  Unlike decoding, this is fully pure.
-}
encodeUcamB64 :: ByteString -> UcamBase64BS
encodeUcamB64 = convertB64Ucam . B64U . B.encode

encodeUcamB64L :: BSL.ByteString -> UcamBase64BSL
encodeUcamB64L = convertB64UcamL . B64UL . BL.encode

{-|
  Extract ascii text.

  TODO Use Haskell’s utf7 functions
-}
decodeASCII' :: ASCII -> Text
decodeASCII' = T.filter isAscii . unASCII
