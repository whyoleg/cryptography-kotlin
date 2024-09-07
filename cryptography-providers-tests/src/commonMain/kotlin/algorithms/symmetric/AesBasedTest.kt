/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*

abstract class AesBasedTest<A : AES<*>>(
    private val algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : ProviderTest(provider) {

    protected inner class AesTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: A,
        val keySize: BinarySize,
    ) : AlgorithmTestScope<A>(logger, context, provider, algorithm)

    protected fun runTestForEachKeySize(block: suspend AesTestScope.() -> Unit) = testAlgorithm(algorithmId) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.inBits)) return@generateSymmetricKeySize

            block(AesTestScope(logger, context, provider, algorithm, keySize))
        }
    }
}
