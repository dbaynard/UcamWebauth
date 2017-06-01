---
title:  Ucam Webauth  
author: David Baynard  
date:   01 Jun 2017  
fontfamily:   libertine
csl:    chemical-engineering-science.csl
link-citations: true
abstract: |  
    
...

# <https://raven.cam.ac.uk/project/>

The University of Cambridge _Raven_ service uses the _Ucam Webauth_ protocol.

This repository contains a number of Haskell libraries to interact with this system.

# ucam-webauth

This implements data types for the client authentication protocol.

There is an internal module which is *not* recommended for use.
Its only purpose is to split the core functionality among packages for minimal ghcjs dependencies.

# ucam-webauth

This implements the client authentication protocol; specifically, the validation.

# raven-wai

This adds [wai](//hackage.haskell.org/package/wai) middleware enabling authentication using _Raven_.

# servant-raven

API combinators for [servant](//hackage.haskell.org/package/servant), using [servant-auth](//hackage.haskell.org/package/servant-auth).

# servant-raven-server

The handlers for [servant](//hackage.haskell.org/package/servant).
