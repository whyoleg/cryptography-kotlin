/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val ivSize = 12
private const val maxPlaintextSize = 10000
private const val maxAssociatedDataSize = 10000

abstract class ChaCha20Poly1305CompatibilityTest(provider: CryptographyProvider) :
    CompatibilityTest<ChaCha20Poly1305>(ChaCha20Poly1305, provider) {

    @Serializable
    private data class CipherParameters(
        val iv: SerializableByteString?,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<ChaCha20Poly1305>.generate(isStressTest: Boolean) {
        val associatedDataIterations = when {
            isStressTest -> 10
            else         -> 3
        }
        val cipherIterations = when {
            isStressTest -> 10
            else         -> 3
        }
        val ivIterations = when {
            isStressTest -> 10
            else         -> 3
        }

        val parametersList = buildList {
            repeat(ivIterations) {
                val parameters = CipherParameters(ByteString(CryptographyRandom.nextBytes(ivSize)))
                val id = api.ciphers.saveParameters(parameters)
                add(id to parameters)
            }
        }

        generateKeys(isStressTest) { key, keyReference ->
            parametersList.forEach { (cipherParametersId, parameters) ->
                logger.log { "parameters = $parameters" }
                val cipher = key.cipher()
                repeat(associatedDataIterations) { adIndex ->
                    val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                    logger.log { "associatedData.size = $associatedDataSize" }
                    val associatedData = associatedDataSize?.let(CryptographyRandom::nextBytes)?.let(::ByteString)
                    repeat(cipherIterations) {
                        val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                        logger.log { "plaintext.size      = $plaintextSize" }
                        val plaintext = ByteString(CryptographyRandom.nextBytes(plaintextSize))

                        val ciphertext = when (val iv = parameters.iv) {
                            null -> {
                                val ciphertext = cipher.encrypt(plaintext, associatedData)
                                logger.log { "ciphertext.size = ${ciphertext.size}" }
                                assertContentEquals(plaintext, cipher.decrypt(ciphertext, associatedData), "Initial Decrypt")
                                ciphertext
                            }
                            else -> {
                                val ciphertext = cipher/*.resetIv(context)*/.encryptWithIv(iv, plaintext, associatedData)
                                logger.log { "ciphertext.size = ${ciphertext.size}" }
                                assertContentEquals(plaintext, cipher.decryptWithIv(iv, ciphertext, associatedData), "Initial Decrypt")
                                ciphertext
                            }
                        }

                        api.ciphers.saveData(
                            cipherParametersId,
                            AuthenticatedCipherData(keyReference, associatedData, plaintext, ciphertext)
                        )
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<ChaCha20Poly1305>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (iv), parametersId, _ ->
            api.ciphers.getData<AuthenticatedCipherData>(parametersId) { (keyReference, associatedData, plaintext, ciphertext), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher()

                    when (iv) {
                        null -> {
                            assertContentEquals(plaintext, cipher.decrypt(ciphertext, associatedData), "Decrypt")
                            assertContentEquals(
                                plaintext,
                                cipher.decrypt(cipher.encrypt(plaintext, associatedData), associatedData),
                                "Encrypt-Decrypt"
                            )
                        }
                        else -> {
                            assertContentEquals(plaintext, cipher.decryptWithIv(iv, ciphertext, associatedData), "Decrypt")
                            assertContentEquals(
                                plaintext,
                                cipher.decryptWithIv(
                                    iv,
                                    cipher/*.resetIv(context)*/.encryptWithIv(iv, plaintext, associatedData),
                                    associatedData
                                ),
                                "Encrypt-Decrypt"
                            )
                        }
                    }
                }
            }
        }
    }

    protected suspend fun CompatibilityTestScope<ChaCha20Poly1305>.generateKeys(
        isStressTest: Boolean,
        block: suspend (key: ChaCha20Poly1305.Key, keyReference: TestReference) -> Unit,
    ) {
        val keyIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val keyParametersId = api.keys.saveParameters(TestParameters.Empty)
        algorithm.keyGenerator().generateKeys(keyIterations) { key ->
            val keyReference = api.keys.saveData(
                keyParametersId,
                KeyData(key.encodeTo(ChaCha20Poly1305.Key.Format.entries, ::supportsKeyFormat))
            )
            block(key, keyReference)
        }
    }

    protected suspend fun CompatibilityTestScope<ChaCha20Poly1305>.validateKeys() = algorithm.keyDecoder().let { keyDecoder ->
        buildMap {
            api.keys.getParameters<TestParameters.Empty> { _, parametersId, _ ->
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = ChaCha20Poly1305.Key.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            ChaCha20Poly1305.Key.Format.RAW -> assertContentEquals(
                                bytes,
                                key.encodeToByteString(format),
                                "Key $format encoding"
                            )
                            ChaCha20Poly1305.Key.Format.JWK -> {} //no check for JWK yet
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
    }
}

// GCM mode on JDK has a check which tries to prevent reuse of the same IV with the same key.
// we need to set random IV first to be able to reuse IV for different plaintext for the same key
//private suspend fun IvAuthenticatedCipher.resetIv(context: TestContext): IvAuthenticatedCipher {
//    if (context.provider.isJdk) Encryptor.encrypt(ByteString())
//    return this
//}
