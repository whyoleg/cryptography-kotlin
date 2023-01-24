package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.test.utils.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 10

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
                val keyReference = api.keys.saveData(keyParametersId, KeyData {
                    put(StringKeyFormat.RAW, key.encodeTo(AES.Key.Format.RAW))
                    if (supportsJwk()) put(StringKeyFormat.JWK, key.encodeTo(AES.Key.Format.JWK))
                })
                block(key, keyReference, keyParameters)
            }
        }
    }

    protected suspend fun CompatibilityTestContext<A>.validateKeys() = algorithm.keyDecoder().let { keyDecoder ->
        buildMap {
            api.keys.getParameters<KeyParameters> { (keySize), parametersId ->
                if (!supportsKeySize(keySize)) return@getParameters

                api.keys.getData<KeyData>(parametersId) { (formats), keyReference ->
                    val keys = keyDecoder.decodeFrom(formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.RAW -> AES.Key.Format.RAW
                            StringKeyFormat.JWK -> AES.Key.Format.JWK.takeIf { supportsJwk() }
                            else                -> error("Unsupported key format: $stringFormat")
                        }
                    }
                    keys.forEach { key ->
                        formats[StringKeyFormat.RAW]?.let { bytes ->
                            assertContentEquals(bytes, key.encodeTo(AES.Key.Format.RAW), "Key RAW encoding")
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
    }
}
