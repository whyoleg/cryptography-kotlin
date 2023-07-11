/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.provider.*
import kotlinx.serialization.*

@Serializable
data class TestContext(
    val platform: TestPlatform,
    val provider: TestProvider,
)

internal fun TestContext(provider: CryptographyProvider): TestContext = TestContext(
    platform = currentTestPlatform,
    provider = when (provider.name) {
        "WebCrypto" -> TestProvider.WebCrypto
        "JDK"       -> TestProvider.JDK.Default
        "JDK (BC)"  -> TestProvider.JDK.BouncyCastle
        "Apple"     -> TestProvider.Apple
        else        -> when {
            provider.name.startsWith("OpenSSL3") -> TestProvider.OpenSSL3(
                version = provider.name.substringAfter("(").substringBeforeLast(")")
            )
            else                                 -> error("Unsupported provider")
        }
    }
)
