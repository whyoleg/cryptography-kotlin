/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package bom

val libraries
    get() = listOf(
        ":cryptography-random",
        ":cryptography-core",
        ":cryptography-jdk",
        ":cryptography-apple",
        ":cryptography-webcrypto",
        ":cryptography-openssl3-api",
        ":cryptography-openssl3-shared",
        ":cryptography-openssl3-prebuilt",
    )
