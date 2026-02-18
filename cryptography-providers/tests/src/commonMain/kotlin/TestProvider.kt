/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import kotlinx.serialization.*

@Serializable
sealed class TestProvider {
    @Serializable
    sealed class JDK : TestProvider() {
        @SerialName("jdk.default")
        @Serializable
        data object Default : JDK() {
            override fun toString(): String = "JDK.Default"
        }

        @SerialName("jdk.bc")
        @Serializable
        data object BouncyCastle : JDK() {
            override fun toString(): String = "JDK.BouncyCastle"
        }
    }

    @SerialName("webcrypto")
    @Serializable
    data object WebCrypto : TestProvider()

    @SerialName("apple")
    @Serializable
    data object Apple : TestProvider()

    @SerialName("openssl3")
    @Serializable
    data class OpenSSL3(val version: String) : TestProvider()

    @SerialName("cryptokit")
    @Serializable
    data object CryptoKit : TestProvider()
}

val TestProvider.isJdk: Boolean get() = this is TestProvider.JDK
val TestProvider.isJdkDefault: Boolean get() = this == TestProvider.JDK.Default
val TestProvider.isBouncyCastle: Boolean get() = this == TestProvider.JDK.BouncyCastle
val TestProvider.isWebCrypto: Boolean get() = this == TestProvider.WebCrypto
val TestProvider.isApple: Boolean get() = this == TestProvider.Apple
val TestProvider.isCryptoKit: Boolean get() = this == TestProvider.CryptoKit
val TestProvider.isOpenssl3: Boolean get() = this is TestProvider.OpenSSL3
inline fun TestProvider.isOpenssl3(block: TestProvider.OpenSSL3.() -> Boolean): Boolean = this is TestProvider.OpenSSL3 && block(this)
