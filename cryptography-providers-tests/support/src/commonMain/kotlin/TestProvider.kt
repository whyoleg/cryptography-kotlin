/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.provider.*
import kotlinx.serialization.*

expect val availableProviders: List<CryptographyProvider>

@Serializable
sealed class TestProvider {
    @Serializable
    sealed class JDK : TestProvider() {
        @Serializable
        data object Default : TestProvider() {
            override fun toString(): String = "JDK.Default"
        }

        @Serializable
        data object BouncyCastle : TestProvider() {
            override fun toString(): String = "JDK.BouncyCastle"
        }
    }

    @Serializable
    data object WebCrypto : TestProvider()

    @Serializable
    data object Apple : TestProvider()

    @Serializable
    data class OpenSSL3(val version: String) : TestProvider()
}

val TestProvider.isJdk: Boolean get() = this is TestProvider.JDK
val TestProvider.isJdkDefault: Boolean get() = this == TestProvider.JDK.Default
val TestProvider.isBouncyCastle: Boolean get() = this == TestProvider.JDK.BouncyCastle
val TestProvider.isWebCrypto: Boolean get() = this == TestProvider.WebCrypto
val TestProvider.isApple: Boolean get() = this == TestProvider.Apple
val TestProvider.isOpenssl3: Boolean get() = this is TestProvider.OpenSSL3
