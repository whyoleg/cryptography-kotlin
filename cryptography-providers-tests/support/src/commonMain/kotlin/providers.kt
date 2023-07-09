/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.provider.*

expect val availableProviders: List<CryptographyProvider>

val CryptographyProvider.isWebCrypto: Boolean
    get() = name == "WebCrypto"

val CryptographyProvider.isJdkDefault: Boolean
    get() = name == "JDK"

val CryptographyProvider.isBouncyCastle: Boolean
    get() = name == "JDK (BC)"

val CryptographyProvider.isApple: Boolean
    get() = name == "Apple"

val CryptographyProvider.isOpenssl3: Boolean
    get() = name.startsWith("OpenSSL3")
