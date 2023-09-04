/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.bom

val artifacts
    get() = listOf(
        "cryptography-random",
        "cryptography-core",
        "cryptography-provider-jdk",
        "cryptography-provider-apple",
        "cryptography-provider-webcrypto",
        "cryptography-provider-openssl3-api",
        "cryptography-provider-openssl3-shared",
        "cryptography-provider-openssl3-prebuilt",
    )
