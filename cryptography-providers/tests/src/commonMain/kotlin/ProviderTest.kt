/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import kotlinx.coroutines.test.*
import kotlin.time.*
import kotlin.time.Duration.Companion.minutes

abstract class ProviderTest(provider: CryptographyProvider) {

    private val timeout: Duration = 60.minutes
    private val logger = TestLogger(enabled = false, tag = provider.name)
    private val context = TestContext(
        platform = currentTestPlatform,
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
                else                                 -> error("Unsupported provider")
            }
        }
    )
    private val scope = ProviderTestScope(logger, context, provider)

    fun testWithProvider(block: suspend ProviderTestScope.() -> Unit): TestResult = runTest(timeout = timeout) {
        scope.block()
    }

    fun <A : CryptographyAlgorithm> testWithAlgorithm(
        algorithmId: CryptographyAlgorithmId<A>,
        block: suspend AlgorithmTestScope<A>.() -> Unit,
    ): TestResult = testWithProvider {
        if (!supports(algorithmId)) return@testWithProvider

        val logger = logger.child(algorithmId.name)
        val algorithm = provider.getOrNull(algorithmId) ?: run {
            logger.print("not supported")
            return@testWithProvider
        }
        logger.print("START")
        AlgorithmTestScope(logger, context, provider, algorithm).block()
        logger.print("COMPLETE")
    }
}
