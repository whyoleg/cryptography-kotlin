/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.behavior

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.support.*

abstract class AesTest<A : AES<*>>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {

    protected inner class AesTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: A,
        val keySize: SymmetricKeySize,
    ) : AlgorithmTestScope<A>(logger, context, provider, algorithm)

    protected fun runTestForEachKeySize(block: suspend AesTestScope.() -> Unit) = runTestForEachAlgorithm(algorithmId) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize

            block(AesTestScope(logger, context, provider, algorithm, keySize))
        }
    }
}
