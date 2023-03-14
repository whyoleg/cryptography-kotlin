/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package bom

val libraries
    get() = listOf(
        ":cryptography-random",
        ":cryptography-core",
        ":cryptography-providers:cryptography-jdk",
        ":cryptography-providers:cryptography-apple",
        ":cryptography-providers:cryptography-webcrypto",
        ":cryptography-providers:cryptography-openssl3:cryptography-openssl3-api",
        ":cryptography-providers:cryptography-openssl3:cryptography-openssl3-shared",
        ":cryptography-providers:cryptography-openssl3:cryptography-openssl3-prebuilt",
    )
