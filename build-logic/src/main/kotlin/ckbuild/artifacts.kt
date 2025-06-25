/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

// all artifacts that are published and documentable
val artifacts
    get() = listOf(
        "cryptography-bigint",
        "cryptography-random",
        "cryptography-serialization-pem",
        "cryptography-serialization-asn1",
        "cryptography-serialization-asn1-modules",
        "cryptography-core",
        "cryptography-provider-base",
        "cryptography-provider-jdk",
        "cryptography-provider-apple",
        "cryptography-provider-cryptokit",
        "cryptography-provider-webcrypto",
        "cryptography-provider-openssl3-api",
        "cryptography-provider-openssl3-shared",
        "cryptography-provider-openssl3-prebuilt",
    )
