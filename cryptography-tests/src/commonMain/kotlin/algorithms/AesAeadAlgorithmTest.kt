/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*

private const val AES_AEAD_DEFAULT_IV_SIZE = 12

typealias AesTagSizeTestGroupValidator = TestGroupValidator<AesTagSizeTestParameters, CipherTestDataValidator>

@Serializable
data class AesTagSizeTestParameters(val tagSizeBits: Int) : TestParameters {
    override val id: String get() = "tag-$tagSizeBits"
}

// GCM and CCM: AES-* -> [key size] -> [key] -> [tag size] -> [data]
abstract class AesAeadAlgorithmTest<A : AES<K>, K : AES.Key>(
    provider: CryptographyProvider,
    algorithmId: CryptographyAlgorithmId<A>,
    algorithmLimitation: (TestLimitationScope.() -> TestLimitation?)?,
    private val tagSizes: List<Int>,
    private val ivSizes: List<Int>,
) : AesAlgorithmTest<A, K, AesTagSizeTestGroupValidator>(provider, algorithmId, algorithmLimitation) {

    protected abstract fun cipher(key: K, tagSize: BinarySize): IvAuthenticatedCipher

    // limitation of the cipher creation for the tag size
    protected open fun TestLimitationScope.tagSizeLimitation(tagSizeBits: Int): TestLimitation? = null

    final override fun TestValidatorScope.keyValidator(keys: List<K>): AesTagSizeTestGroupValidator = group<AesTagSizeTestParameters, _>(
        limitation = { (tagSizeBits) -> tagSizeLimitation(tagSizeBits) },
    ) { (tagSizeBits) ->
        val tagSize = tagSizeBits.bits
        val ciphers = keys.map { cipher(it, tagSize) }
        ciphertexts(
            encryptors = ciphers,
            decryptors = ciphers,
            ivSize = AES_AEAD_DEFAULT_IV_SIZE,
            ciphertextSize = { it + tagSize.inBytes },
            deterministic = false,
        )
    }

    context(context: TestGenerationContext)
    final override suspend fun AesTagSizeTestGroupValidator.generateRandom(key: K, otherKey: K) {
        tagSizes.forEach { tagSizeBits ->
            group(AesTagSizeTestParameters(tagSizeBits)) {
                val cipher = cipher(key, tagSizeBits.bits)
                generateCiphertexts(cipher, listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) })
                generateCiphertexts(
                    encryptor = cipher,
                    plaintextSizes = listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) },
                    associatedDataSize = 100,
                )
                ivSizes.forEach { ivSize ->
                    generateCiphertexts(cipher, listOf(0, 16, 1000), ivSize = ivSize)
                    generateCiphertexts(cipher, listOf(0, 16, 1000), ivSize = ivSize, associatedDataSize = 16)
                }
                // shorter than IV + tag
                invalidCiphertexts(0, AES_AEAD_DEFAULT_IV_SIZE + tagSizeBits.bits.inBytes - 1)
                otherKeyCiphertext(cipher(otherKey, tagSizeBits.bits))
            }
        }
    }

    context(context: TestGenerationContext)
    final override suspend fun AesTagSizeTestGroupValidator.generateLarge(key: K) {
        group(AesTagSizeTestParameters(128)) {
            generateCiphertexts(cipher(key, 128.bits), listOf(1_000_000), associatedDataSize = 100)
        }
    }
}
