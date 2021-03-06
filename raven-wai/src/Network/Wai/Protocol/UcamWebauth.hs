{-|
Module      : Network.Wai.Protocol.UcamWebauth
Description : Authenticate using the Ucam-Webauth protocol
Maintainer  : David Baynard <ucamwebauth@baynard.me>

This module implements the client form of the University of Cambridge’s Ucam-Webauth protocol,
as in the link below. The protocol is a handshake between the

  [@WAA@], /i.e./ application wishing to authenticate (whatever uses this module!), and the
  [@WLS@], /i.e./ server which can authenticate the user

<https://raven.cam.ac.uk/project/waa2wls-protocol.txt>

See the "Network.Wai.Protocol.Raven.Auth" module for a specific implementation, and
"Network.Wai.Protocol.Raven.Example" for an example.

It is necessary to store the relevant public keys, as described in the documentation
for 'readRSAKeyFile'.

-}

{-# LANGUAGE
    PackageImports
  , OverloadedStrings
  #-}

module Network.Wai.Protocol.UcamWebauth
  ( lookUpWLSResponse
  ) where

import           "base"       Control.Monad
import           "bytestring" Data.ByteString (ByteString)
import qualified "containers" Data.Map.Strict as M
import           "wai"        Network.Wai

------------------------------------------------------------------------------
-- * Top level functions

{-|
  Extract the 'ByteString' response from the @WLS@ in the full response header.
-}
lookUpWLSResponse :: Request -> Maybe ByteString
lookUpWLSResponse = join . M.lookup "WLS-Response" . M.fromList . queryString
