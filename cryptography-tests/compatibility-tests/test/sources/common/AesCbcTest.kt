package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 10
private const val cipherIterations = 10
private const val maxPlaintextSize = 10000
private const val blockSize = 16 //for no padding

private fun Int.withPadding(padding: Boolean): Int = if (padding) this else this + blockSize - this % blockSize

class AesCbcTest : CompatibilityTest<AES.CBC>(AES.CBC) {

    @Serializable
    private data class KeyParameters(val keySizeBits: Int) : TestParameters

    @Serializable
    private data class CipherParameters(val padding: Boolean) : TestParameters

    override suspend fun CompatibilityTestContext<AES.CBC>.generate() {
        val paddings = buildList {
            generateBoolean { padding ->
                if (!supportsPadding(padding)) return@generateBoolean

                val id = api.ciphers.saveParameters(CipherParameters(padding))
                add(id to padding)
            }
        }

        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize

            val keyParametersId = api.keys.saveParameters(KeyParameters(keySize.value.inBits))
            algorithm.keyGenerator(keySize).generateKeys(keyIterations) { key ->
                val keyReference = api.keys.saveData(keyParametersId, KeyData {
                    put(StringKeyFormat.RAW, key.encodeTo(AES.Key.Format.RAW))
                    if (provider.supportsJwk) put(StringKeyFormat.JWK, key.encodeTo(AES.Key.Format.JWK))
                })
                paddings.forEach { (cipherParametersId, padding) ->
                    logger.log("padding = $padding")
                    val cipher = key.cipher(padding)
                    repeat(cipherIterations) {
                        val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize).withPadding(padding)
                        logger.log("plaintext.size  = $plaintextSize")
                        val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                        val ciphertext = cipher.encrypt(plaintext)
                        logger.log("ciphertext.size = ${ciphertext.size}")

                        assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Initial Decrypt")

                        api.ciphers.saveData(cipherParametersId, CipherData(keyReference, plaintext, ciphertext))
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestContext<AES.CBC>.validate() {
        val keyDecoder = algorithm.keyDecoder()

        val keys = buildMap {
            api.keys.getParameters<KeyParameters> { (keySize), parametersId ->
                if (!supportsKeySize(keySize)) return@getParameters

                api.keys.getData<KeyData>(parametersId) { (formats), keyReference ->
                    val keys = keyDecoder.decodeFrom(formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.RAW -> AES.Key.Format.RAW
                            StringKeyFormat.JWK -> AES.Key.Format.JWK.takeIf { provider.supportsJwk }
                            else                -> error("Unsupported key format: $stringFormat") //TODO
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

        api.ciphers.getParameters<CipherParameters> { (padding), parametersId ->
            if (!supportsPadding(padding)) return@getParameters

            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _ ->
                keys.getValue(keyReference).forEach { key ->
                    val cipher = key.cipher(padding)
                    assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Decrypt")
                    assertContentEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext)), "Encrypt-Decrypt")
                }
            }
        }
    }
}
