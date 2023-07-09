/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.behavior

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.providers.tests.support.*

abstract class AesTest<A : AES<*>>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {

    protected inner class AesTestContext(
        logger: TestLogger,
        provider: CryptographyProvider,
        algorithm: A,
        val keySize: SymmetricKeySize,
    ) : AlgorithmTestContext<A>(logger, provider, algorithm)


    protected fun runTestForEachKeySize(block: suspend AesTestContext.() -> Unit) = runTestForEachAlgorithm(algorithmId) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize

            block(AesTestContext(logger, provider, algorithm, keySize))
        }
    }
}
