/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.testhost.*
import kotlinx.serialization.*
import kotlin.uuid.*

// describes where the test data was generated; stored as `[run-id].json`
@Serializable
data class TestEnvironment(
    val platform: TestPlatform,
    val provider: TestProvider,
)

@Serializable
sealed class TestProvider {
    @Serializable
    sealed class JDK : TestProvider() {
        @SerialName("jdk.default")
        @Serializable
        data object Default : JDK()

        @SerialName("jdk.bc")
        @Serializable
        data object BouncyCastle : JDK()
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

internal fun TestEnvironment(provider: CryptographyProvider): TestEnvironment = TestEnvironment(
    platform = TestPlatform.current(),
    provider = when (provider.name) {
        "WebCrypto" -> TestProvider.WebCrypto
        "JDK"       -> TestProvider.JDK.Default
        "JDK (BC)"  -> TestProvider.JDK.BouncyCastle
        "Apple"     -> TestProvider.Apple
        "CryptoKit" -> TestProvider.CryptoKit
        else        -> when {
            provider.name.startsWith("OpenSSL3") -> TestProvider.OpenSSL3(
                version = provider.name.substringAfter("(").substringBeforeLast(")")
            )
            else                                 -> error("Unsupported provider: ${provider.name}")
        }
    }
)

// one run per provider in the current process; V7 for sorting of runs
@OptIn(ExperimentalUuidApi::class)
private val runIds = mutableMapOf<String, String>()

@OptIn(ExperimentalUuidApi::class)
internal fun currentRunId(provider: CryptographyProvider): String = runIds.getOrPut(provider.name) {
    Uuid.generateV7().toHexDashString()
}
