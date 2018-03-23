{-|
Module      : Extra.Servant.Redirect.API
Description : Redirects within the API
Maintainer  : David Baynard <davidbaynard@gmail.com>

Based on Alp Mestanogullari’s approach to (success) redirects, from
<https://gist.github.com/alpmestan/757094ecf9401f85c5ba367ca20b8900>

 -}

{-# LANGUAGE
    PackageImports
  , DataKinds
  , TypeInType
  , TypeOperators
  #-}

module Extra.Servant.Redirect.API
  ( Redirect
  , PostRedirect
  , AuthCookieRedirect
  ) where

import "base"    GHC.TypeLits
import "servant" Servant.API

-- | Redirect to 'loc'.
--
-- Handler implementations determine the kind of 'loc'.
type Redirect (method :: StdMethod) (code :: Nat) contentTypes (loc :: k)
    = Verb method code contentTypes (Headers '[Header "Location" loc] NoContent)

-- | Redirect using JSON and a POST request.
type PostRedirect (code :: Nat) (loc :: k)
    = Redirect 'POST code '[JSON] loc

-- | Redirect suitable for setting cookies on authentication.
type AuthCookieRedirect (method :: StdMethod) (loc :: k)
    = Redirect method 302 '[PlainText] loc
