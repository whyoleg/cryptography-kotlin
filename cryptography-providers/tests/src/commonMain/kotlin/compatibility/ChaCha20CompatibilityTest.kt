/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val nonceSize = 12
private const val maxPlaintextSize = 10000

abstract class ChaCha20CompatibilityTest(provider: CryptographyProvider) :
    CompatibilityTest<ChaCha20>(ChaCha20, provider) {

    @Serializable
    private data class CipherParameters(
        val iv: SerializableByteString?,
    ) : TestParameters {
        override fun toString(): String = "CipherParameters(iv.size=${iv?.size})"
    }

    override suspend fun CompatibilityTestScope<ChaCha20>.generate(isStressTest: Boolean) {
        val cipherIterations = when {
            isStressTest -> 10
            else         -> 3
        }
        val ivIterations = when {
            isStressTest -> 10
            else         -> 3
        }

        val parametersList = buildList {
            (List(ivIterations) { ByteString(CryptographyRandom.nextBytes(nonceSize)) } + listOf(null)).forEach { iv ->
                val parameters = CipherParameters(iv)
                val id = api.ciphers.saveParameters(parameters)
                add(id to parameters)
            }
        }

        generateKeys(isStressTest) { key, keyReference ->
            parametersList.forEach { (cipherParametersId, parameters) ->
                logger.log { "parameters = $parameters" }
                val cipher = key.cipher()
                repeat(cipherIterations) {
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                    logger.log { "plaintext.size  = $plaintextSize" }
                    val plaintext = ByteString(CryptographyRandom.nextBytes(plaintextSize))

                    val ciphertext = when (val iv = parameters.iv) {
                        null -> {
                            val ciphertext = cipher.encrypt(plaintext)
                            logger.log { "ciphertext.size = ${ciphertext.size}" }
                            assertContentEquals(
                                plaintext,
                                cipher.resetIv(context).decrypt(ciphertext),
                                "Initial Decrypt"
                            )
                            ciphertext
                        }
                        else -> {
                            val ciphertext = cipher.resetIv(context).encryptWithIv(iv, plaintext)
                            logger.log { "ciphertext.size = ${ciphertext.size}" }
                            assertContentEquals(
                                plaintext,
                                cipher.resetIv(context).decryptWithIv(iv, ciphertext),
                                "Initial Decrypt"
                            )
                            ciphertext
                        }
                    }

                    api.ciphers.saveData(cipherParametersId, CipherData(keyReference, plaintext, ciphertext))
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<ChaCha20>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (iv), parametersId, _ ->
            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher()
                    when (iv) {
                        null -> {
                            assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Decrypt")

                            val newCiphertext = cipher.encrypt(plaintext)
                            assertContentEquals(
                                plaintext,
                                cipher.resetIv(context).decrypt(newCiphertext),
                                "Encrypt-Decrypt"
                            )
                        }
                        else -> {
                            assertContentEquals(plaintext, cipher.resetIv(context).decryptWithIv(iv, ciphertext), "Decrypt")

                            val newCiphertext = cipher.resetIv(context).encryptWithIv(iv, plaintext)
                            assertContentEquals(
                                plaintext,
                                cipher.resetIv(context).decryptWithIv(iv, newCiphertext),
                                "Encrypt-Decrypt"
                            )
                        }
                    }
                }
            }
        }
    }

    private suspend fun CompatibilityTestScope<ChaCha20>.generateKeys(
        isStressTest: Boolean,
        block: suspend (key: ChaCha20.Key, keyReference: TestReference) -> Unit,
    ) {
        val keyIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val keyParametersId = api.keys.saveParameters(TestParameters.Empty)
        algorithm.keyGenerator().generateKeys(keyIterations) { key ->
            val keyReference = api.keys.saveData(
                keyParametersId,
                KeyData(key.encodeTo(ChaCha20.Key.Format.entries, ::supportsFormat))
            )
            block(key, keyReference)
        }
    }

    private suspend fun CompatibilityTestScope<ChaCha20>.validateKeys() = algorithm.keyDecoder().let { keyDecoder ->
        buildMap {
            api.keys.getParameters<TestParameters.Empty> { _, parametersId, _ ->
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = ChaCha20.Key.Format::valueOf,
                        supports = ::supportsFormat
                    ) { key, format, bytes ->
                        when (format) {
                            ChaCha20.Key.Format.RAW -> assertContentEquals(
                                bytes,
                                key.encodeToByteString(format),
                                "Key $format encoding"
                            )
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
    }
}

// ChaCha20 mode on JDK has a check which tries to prevent reuse of the same nonce with the same key.
private suspend fun IvCipher.resetIv(context: TestContext): IvCipher {
    if (context.provider.isJdk) {
        val initial = encrypt(ByteString())
        encrypt(ByteString()) // discarded
        decrypt(initial)
    }
    return this
}
