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
import kotlinx.serialization.*

typealias AesPaddingTestGroupValidator = TestGroupValidator<AesPaddingTestParameters, CipherTestDataValidator>

@Serializable
data class AesPaddingTestParameters(val padding: Boolean) : TestParameters {
    override val id: String get() = if (padding) "padding" else "no-padding"
}

// ECB and CBC: AES-* -> [key size] -> [key] -> [padding] -> [data]
abstract class AesPaddingAlgorithmTest<A : AES<K>, K : AES.Key>(
    provider: CryptographyProvider,
    algorithmId: CryptographyAlgorithmId<A>,
    algorithmLimitation: (TestLimitationScope.() -> TestLimitation?)?,
    // IV is prepended to the ciphertext, 0 for ciphers without IV
    private val ivSize: Int,
) : AesAlgorithmTest<A, K, AesPaddingTestGroupValidator>(provider, algorithmId, algorithmLimitation) {

    protected abstract fun cipher(key: K, padding: Boolean): Cipher

    final override fun TestValidatorScope.keyValidator(keys: List<K>): AesPaddingTestGroupValidator = group<AesPaddingTestParameters, _>(
        limitation = { (padding) ->
            when (padding) {
                // all providers fail when creating ciphers
                false if provider.isWebCrypto
                    -> fails("Encryption without padding is not supported")
                else -> null
            }
        },
    ) { (padding) ->
        val ciphers = keys.map { cipher(it, padding) }
        ciphertexts(
            encryptors = ciphers,
            decryptors = ciphers,
            ivSize = ivSize,
            ciphertextSize = { paddedCiphertextSize(it, padding) },
            // without IV, the same plaintext is encrypted into the same ciphertext
            deterministic = ivSize == 0,
        )
    }

    context(context: TestGenerationContext)
    final override suspend fun AesPaddingTestGroupValidator.generateRandom(key: K, otherKey: K) {
        group(AesPaddingTestParameters(padding = true)) {
            generateRandom(
                cipher = cipher(key, padding = true),
                plaintextSizes = listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) },
            )
        }
        group(AesPaddingTestParameters(padding = false)) {
            generateRandom(
                cipher = cipher(key, padding = false),
                // only full blocks
                plaintextSizes = listOf(0, 16, 32, 320, 1600) + List(2) { CryptographyRandom.nextInt(100) * AES_BLOCK_SIZE },
            )
        }
    }

    context(context: TestGenerationContext)
    final override suspend fun AesPaddingTestGroupValidator.generateLarge(key: K) {
        group(AesPaddingTestParameters(padding = true)) {
            generateCiphertexts(cipher(key, padding = true), listOf(1_000_000))
        }
    }

    context(context: TestGenerationContext)
    private suspend fun CipherTestDataValidator.generateRandom(cipher: Cipher, plaintextSizes: List<Int>) {
        generateCiphertexts(cipher, plaintextSizes)
        if (ivSize != 0) generateCiphertexts(cipher, plaintextSizes, ivSize = ivSize)
        when (ivSize) {
            // not aligned to block size
            0    -> invalidCiphertexts(15, 17)
            // shorter than IV, not aligned to block size
            else -> invalidCiphertexts(0, ivSize - 1, ivSize + 15, ivSize + 17)
        }
    }
}

private fun paddedCiphertextSize(plaintextSize: Int, padding: Boolean): Int = when (padding) {
    true  -> (plaintextSize / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE
    false -> plaintextSize
}
