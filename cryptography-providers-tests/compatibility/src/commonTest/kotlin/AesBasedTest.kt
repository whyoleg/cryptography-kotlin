/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.providers.tests.support.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 5

abstract class AesBasedTest<K : AES.Key, A : AES<K>>(
    algorithmId: CryptographyAlgorithmId<A>,
) : CompatibilityTest<A>(algorithmId) {

    @Serializable
    protected data class KeyParameters(val keySizeBits: Int) : TestParameters

    protected suspend fun CompatibilityTestContext<A>.generateKeys(
        block: suspend (key: K, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize

            val keyParameters = KeyParameters(keySize.value.inBits)
            val keyParametersId = api.keys.saveParameters(keyParameters)
            algorithm.keyGenerator(keySize).generateKeys(keyIterations) { key ->
                val keyReference = api.keys.saveData(
                    keyParametersId,
                    KeyData(key.encodeTo(AES.Key.Format.values(), ::supportsKeyFormat))
                )
                block(key, keyReference, keyParameters)
            }
        }
    }

    protected suspend fun CompatibilityTestContext<A>.validateKeys() = algorithm.keyDecoder().let { keyDecoder ->
        buildMap {
            api.keys.getParameters<KeyParameters> { (keySize), parametersId ->
                if (!supportsKeySize(keySize)) return@getParameters

                api.keys.getData<KeyData>(parametersId) { (formats), keyReference ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = AES.Key.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            AES.Key.Format.RAW -> assertContentEquals(bytes, key.encodeTo(format), "Key $format encoding")
                            AES.Key.Format.JWK -> {} //no check for JWK yet
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
    }
}
