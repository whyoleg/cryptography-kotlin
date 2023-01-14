package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.api.*
import dev.whyoleg.cryptography.test.client.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import kotlin.random.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class AesCbcTest {

    @Test
    fun generateData() = runTest {
        supportedProviders.forEach { provider ->
            val algorithm = provider.get(AES.CBC)
            val client = HttpApi(mapOf("provider" to provider.name, "platform" to currentPlatform))

            listOf(
                SymmetricKeySize.B128,
                SymmetricKeySize.B192,
                SymmetricKeySize.B256
            ).filter {
                //TODO why?
                if (provider.isWebCrypto) it != SymmetricKeySize.B192 else true
            }.forEach { keySize ->
                val keyParams = when (keySize) {
                    SymmetricKeySize.B128 -> "128bits"
                    SymmetricKeySize.B192 -> "192bits"
                    SymmetricKeySize.B256 -> "256bits"
                    else                  -> error("Unsupported key size: $keySize")
                }
                val keyGenerator = algorithm.keyGenerator(keySize)
                repeat(10) {
                    val key = keyGenerator.generateKey()
                    val keyId = client.keys.save(
                        algorithm = algorithm.id.name,
                        params = keyParams,
                        data = EncodedKey {
                            put("RAW", key.encodeTo(AES.Key.Format.RAW))
                            if (provider.supportsJwk) put("JWK", key.encodeTo(AES.Key.Format.JWK))
                        }
                    )
                    val cipher = key.cipher(true)
                    repeat(10) {
                        val plaintextSize = CryptographyRandom.nextInt(10000)
                        val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                        val ciphertext = cipher.encrypt(plaintext)

                        cipher.decrypt(ciphertext).assertContentEquals(plaintext)

                        client.ciphers.save(
                            algorithm = algorithm.id.name,
                            params = "PKCS7Padding",
                            data = CipherData(keyId, plaintext, ciphertext),
                            metadata = mapOf("key.params" to keyParams)
                        )
                    }
                }
            }
        }
    }

    @Test
    fun validateData() = runTest {
        supportedProviders.forEach { provider ->
            val algorithm = provider.get(AES.CBC)
            val client = HttpApi(mapOf("provider" to provider.name, "platform" to currentPlatform))

            val keyDecoder = algorithm.keyDecoder()

            client.ciphers.getAll(
                algorithm = algorithm.id.name,
                params = "PKCS7Padding",
            ).forEach { (metadata, encodedCipher) ->
                if (metadata["key.params"] == "192bits" && provider.isWebCrypto) return@forEach //TODO

                val encodedKey = client.keys.get(
                    algorithm = algorithm.id.name,
                    params = metadata["key.params"]!!,
                    id = encodedCipher.keyId
                ).data
                encodedKey.formats.forEach { (stringFormat, data) ->
                    val key = keyDecoder.decodeFrom(
                        format = when (stringFormat) {
                            "RAW" -> AES.Key.Format.RAW
                            "JWK" -> AES.Key.Format.JWK.takeIf { provider.supportsJwk }
                            else  -> error("Unsupported key format: $stringFormat") //TODO
                        },
                        input = data
                    ) ?: return@forEach

                    encodedKey.formats["RAW"]?.let { bytes ->
                        key.encodeTo(AES.Key.Format.RAW).assertContentEquals(bytes)
                    }
                    //TODO: JWK should be checked by JSON equality, and not per bytes (use kx.serialization)

                    key.cipher(true).run {
                        decrypt(encodedCipher.ciphertext).assertContentEquals(encodedCipher.plaintext)
                        decrypt(encrypt(encodedCipher.plaintext)).assertContentEquals(encodedCipher.plaintext)
                    }
                }
            }
        }
    }
}
