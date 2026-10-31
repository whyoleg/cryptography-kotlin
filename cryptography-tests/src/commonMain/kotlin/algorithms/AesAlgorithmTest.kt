/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*
import kotlin.test.*

internal const val AES_BLOCK_SIZE = 16

typealias AesTestGroupValidator<K, V> = TestGroupValidator<AesKeySizeTestParameters, AesKeyTestGroupValidator<K, V>>
typealias AesKeyTestGroupValidator<K, V> = EncodableTestGroupValidator<AES.Key.Format, K, V>

@Serializable
data class AesKeySizeTestParameters(val keySizeBits: Int) : TestParameters {
    override val id: String get() = "$keySizeBits"
}

fun AesKeySizeTestParameters(keySize: BinarySize): AesKeySizeTestParameters = AesKeySizeTestParameters(keySize.inBits)

// AES-* -> [key size] -> [key] -> V (mode specific)
abstract class AesAlgorithmTest<A : AES<K>, K : AES.Key, V : TestInputValidator>(
    provider: CryptographyProvider,
    algorithmId: CryptographyAlgorithmId<A>,
    algorithmLimitation: (TestLimitationScope.() -> TestLimitation?)?,
) : AlgorithmTest<A, AesTestGroupValidator<K, V>>(provider, algorithmId, algorithmLimitation) {

    final override fun TestValidatorScope.validator(algorithm: A): AesTestGroupValidator<K, V> =
        group<AesKeySizeTestParameters, _> { (keySizeBits) ->
            encodables(
                decoder = algorithm.keyDecoder(),
                limitation = { failsIfKeySizeUnsupportedInBrowser(keySizeBits) },
                formats = {
                    raw(AES.Key.Format.RAW, size = keySizeBits.bits.inBytes)
                    jwk(AES.Key.Format.JWK, "kty", "k")
                },
            ) { keys ->
                keyValidator(keys)
            }
        }

    // validator of the key group
    protected abstract fun TestValidatorScope.keyValidator(keys: List<K>): V

    // generates random data for the generated key;
    // `otherKey` is another generated key of the same size, data of which must be rejected by modes which detect it
    context(context: TestGenerationContext)
    protected abstract suspend fun V.generateRandom(key: K, otherKey: K)

    // generates large data for the generated key
    context(context: TestGenerationContext)
    protected abstract suspend fun V.generateLarge(key: K)
    @Test
    fun random() = test("random") { algorithm ->
        listOf(AES.Key.Size.B128, AES.Key.Size.B192, AES.Key.Size.B256).forEach { keySize ->
            group(AesKeySizeTestParameters(keySize)) {
                generateEncodableGroups(algorithm.keyGenerator(keySize), iterations = 2) { key ->
                    generateRandom(key, otherKey = algorithm.keyGenerator(keySize).generateKey())
                }
                // large data is stored and validated by every provider, so it's generated only for a single key
                if (keySize == AES.Key.Size.B256) generateEncodableGroups(algorithm.keyGenerator(keySize), iterations = 1) { key ->
                    generateLarge(key)
                }
            }
        }
    }
}

// https://bugs.chromium.org/p/chromium/issues/detail?id=533699, fails only when generating or decoding keys
private fun TestLimitationScope.failsIfKeySizeUnsupportedInBrowser(keySizeBits: Int): TestLimitation? = when (keySizeBits) {
    192 if provider.isWebCrypto && platform.isBrowser -> fails("192 bits keys are not supported in browsers")
    else                                              -> null
}
