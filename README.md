---
title:  Ucam Webauth  
author: David Baynard  
date:   13 Feb 2019  
...

[![Build Status](https://travis-ci.com/dbaynard/UcamWebauth.svg?branch=develop)](https://travis-ci.com/dbaynard/UcamWebauth)

# <https://raven.cam.ac.uk/project/>

The University of Cambridge _Raven_ service uses the _Ucam Webauth_ protocol.

This repository contains a number of Haskell libraries to interact with this system.

# ucam-webauth

[![Hackage — ucam-webauth](https://img.shields.io/hackage/v/ucam-webauth.svg?style=flat)](https://hackage.haskell.org/package/ucam-webauth)
[![ucam-webauth on Stackage LTS 13](http://stackage.org/package/ucam-webauth/badge/lts-13)](http://stackage.org/lts-13/package/ucam-webauth)
[![ucam-webauth on Stackage Nightly](http://stackage.org/package/ucam-webauth/badge/nightly)](http://stackage.org/nightly/package/ucam-webauth)

This implements the client authentication protocol; specifically, the validation.

# ucam-webauth-types

[![Hackage — ucam-webauth-types](https://img.shields.io/hackage/v/ucam-webauth-types.svg?style=flat)](https://hackage.haskell.org/package/ucam-webauth-types)
[![ucam-webauth-types on Stackage LTS 13](http://stackage.org/package/ucam-webauth-types/badge/lts-13)](http://stackage.org/lts-13/package/ucam-webauth-types)
[![ucam-webauth-types on Stackage Nightly](http://stackage.org/package/ucam-webauth-types/badge/nightly)](http://stackage.org/nightly/package/ucam-webauth-types)

This implements data types for the client authentication protocol.

There is an internal package which is *not* recommended for use.
Its only purpose is to split the core functionality among packages for minimal ghcjs dependencies.

# raven-wai

[![Hackage — raven-wai](https://img.shields.io/hackage/v/raven-wai.svg?style=flat)](https://hackage.haskell.org/package/raven-wai)
[![raven-wai on Stackage LTS 13](http://stackage.org/package/raven-wai/badge/lts-13)](http://stackage.org/lts-13/package/raven-wai)
[![raven-wai on Stackage Nightly](http://stackage.org/package/raven-wai/badge/nightly)](http://stackage.org/nightly/package/raven-wai)

This adds [wai](//hackage.haskell.org/package/wai) middleware enabling authentication using _Raven_.

# rio-servant

[![Hackage — rio-servant](https://img.shields.io/hackage/v/rio-servant.svg?style=flat)](https://hackage.haskell.org/package/rio-servant)
[![rio-servant on Stackage LTS 13](http://stackage.org/package/rio-servant/badge/lts-13)](http://stackage.org/lts-13/package/rio-servant)
[![rio-servant on Stackage Nightly](http://stackage.org/package/rio-servant/badge/nightly)](http://stackage.org/nightly/package/rio-servant)

Use [servant](//hackage.haskell.org/package/servant) with [RIO](//hackage.haskell.org/package/rio)

# servant-raven

[![Hackage — servant-raven](https://img.shields.io/hackage/v/servant-raven.svg?style=flat)](https://hackage.haskell.org/package/servant-raven)
[![servant-raven on Stackage LTS 13](http://stackage.org/package/servant-raven/badge/lts-13)](http://stackage.org/lts-13/package/servant-raven)
[![servant-raven on Stackage Nightly](http://stackage.org/package/servant-raven/badge/nightly)](http://stackage.org/nightly/package/servant-raven)

API combinators for [servant](//hackage.haskell.org/package/servant), using [servant-auth](//hackage.haskell.org/package/servant-auth).

# servant-raven-server

[![Hackage — servant-raven-server](https://img.shields.io/hackage/v/servant-raven-server.svg?style=flat)](https://hackage.haskell.org/package/servant-raven-server)
[![servant-raven-server on Stackage LTS 13](http://stackage.org/package/servant-raven-server/badge/lts-13)](http://stackage.org/lts-13/package/servant-raven-server)
[![servant-raven-server on Stackage Nightly](http://stackage.org/package/servant-raven-server/badge/nightly)](http://stackage.org/nightly/package/servant-raven-server)

The handlers for [servant](//hackage.haskell.org/package/servant).

# servant-redirect

[![Hackage — servant-redirect](https://img.shields.io/hackage/v/servant-redirect.svg?style=flat)](https://hackage.haskell.org/package/servant-redirect)
[![servant-redirect on Stackage LTS 13](http://stackage.org/package/servant-redirect/badge/lts-13)](http://stackage.org/lts-13/package/servant-redirect)
[![servant-redirect on Stackage Nightly](http://stackage.org/package/servant-redirect/badge/nightly)](http://stackage.org/nightly/package/servant-redirect)

Redirect combinators for [servant](//hackage.haskell.org/package/servant), using [servant-auth](//hackage.haskell.org/package/servant-auth).

# servant-redirect-server

[![Hackage — servant-redirect-server](https://img.shields.io/hackage/v/servant-redirect-server.svg?style=flat)](https://hackage.haskell.org/package/servant-redirect-server)
[![servant-redirect-server on Stackage LTS 13](http://stackage.org/package/servant-redirect-server/badge/lts-13)](http://stackage.org/lts-13/package/servant-redirect-server)
[![servant-redirect-server on Stackage Nightly](http://stackage.org/package/servant-redirect-server/badge/nightly)](http://stackage.org/nightly/package/servant-redirect-server)

The handlers for [servant-redirect](//hackage.haskell.org/package/servant-redirect).
