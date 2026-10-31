/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*

// CTR, CFB, CFB8, OFB: AES-* -> [key size] -> [key] -> [data]
abstract class AesStreamModeAlgorithmTest<A : AES<K>, K : AES.Key>(
    provider: CryptographyProvider,
    algorithmId: CryptographyAlgorithmId<A>,
    algorithmLimitation: (TestLimitationScope.() -> TestLimitation?)?,
) : AesAlgorithmTest<A, K, CipherTestDataValidator>(provider, algorithmId, algorithmLimitation) {

    protected abstract fun cipher(key: K): IvCipher

    final override fun TestValidatorScope.keyValidator(keys: List<K>): CipherTestDataValidator {
        val ciphers = keys.map { cipher(it) }
        return ciphertexts(
            encryptors = ciphers,
            decryptors = ciphers,
            ivSize = AES_BLOCK_SIZE,
            ciphertextSize = { it },
            deterministic = false,
        )
    }

    context(context: TestGenerationContext)
    final override suspend fun CipherTestDataValidator.generateRandom(key: K, otherKey: K) {
        val cipher = cipher(key)
        generateCiphertexts(cipher, listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) })
        generateCiphertexts(
            encryptor = cipher,
            plaintextSizes = listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) },
            ivSize = AES_BLOCK_SIZE,
        )
        // shorter than IV
        invalidCiphertexts(0, AES_BLOCK_SIZE - 1)
    }

    context(context: TestGenerationContext)
    final override suspend fun CipherTestDataValidator.generateLarge(key: K) {
        generateCiphertexts(cipher(key), listOf(1_000_000))
    }
}
