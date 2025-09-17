/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*

abstract class AesBasedTest<A : AES<*>>(
    algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : AlgorithmTest<A>(algorithmId, provider), CipherTest {

    protected inner class AesTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: A,
        val keySize: BinarySize,
    ) : AlgorithmTestScope<A>(logger, context, provider, algorithm)

    protected fun runTestForEachKeySize(block: suspend AesTestScope.() -> Unit) = testWithAlgorithm {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.inBits)) return@generateSymmetricKeySize

            block(AesTestScope(logger, context, provider, algorithm, keySize))
        }
    }

}
