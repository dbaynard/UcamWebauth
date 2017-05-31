---
title:  Ucam Webauth  
author: David Baynard  
date:   31 May 2017  
fontfamily:   libertine
csl:    chemical-engineering-science.csl
link-citations: true
abstract: |  
    
...

# <https://raven.cam.ac.uk/project/>

The University of Cambridge _Raven_ service uses the _Ucam Webauth_ protocol.

This repository contains a number of Haskell libraries to interact with this system.

# ucam-webauth

This implements the client authentication protocol.

# raven-wai

This adds [wai](//hackage.haskell.org/package/wai) middleware enabling authentication using _Raven_.

# servant-raven

API combinators for [servant](//hackage.haskell.org/package/servant), using [servant-auth](//hackage.haskell.org/package/servant-auth).

# servant-raven-server

The handlers for [servant](//hackage.haskell.org/package/servant).
