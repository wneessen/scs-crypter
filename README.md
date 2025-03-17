<!--
SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>

SPDX-License-Identifier: MIT
-->

# scs-crypter

## SCS Codec Interface for session encryption using AEAD ciphers

## Overview

The `scscrypter` package provides an implementation of the Codec interface
for [Alex Edwards' SCS: HTTP Session Management](https://github.com/alexedwards/scs). It enables the use of
AEAD ciphers to encrypt and authenticate session data before storing them in any supported SCS session storage.

## Usage

```go
package main

import (
        "log"
        "net/http"

        "github.com/alexedwards/scs/v2"
        "github.com/wneessen/scs-crypter"
)

func main() {
    // 256 bit random key (DO NOT USE THIS KEY IN YOUR OWN CODE)
    key := []byte{
        0x83, 0xf0, 0x7d, 0xbd, 0x1e, 0x51, 0x7a, 0xfe, 0x1a, 0x42, 0x98, 0x12, 0x4c, 0x30, 0x4b, 0xcc, 
        0x82, 0x76, 0xf6, 0x47, 0xab, 0x8c, 0xaa, 0x50, 0xf2, 0xc1, 0xbf, 0xe2, 0x64, 0xef, 0x6c, 0x12,
    }
    
    // Initialize a AES-256-GCM encrypter 
    encrypter, err := scscrypter.NewAESGCM(key)
    if err != nil {
        log.Fatalf("failed to initalize SCS cypter: %s", err)
    } 
    
    // Initialize a new session manager and set dbenc as Codec 
    sessionManager = scs.New()
    sessionManager.Codec = encrypter
    
    mux := http.NewServeMux()
    mux.HandleFunc("/session", yourSessionHandler)
    http.ListenAndServe(":4000", sessionManager.LoadAndSave(mux))
}
```

## License

This package is licensed under the MIT License. See [LICENSE](../LICENSE) for details.