/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val maxPlaintextSize = 10000

abstract class AesCfbCompatibilityTest(provider: CryptographyProvider) :
    AesBasedCompatibilityTest<AES.CFB.Key, AES.CFB>(AES.CFB, provider) {

    @Serializable
    private data class CipherParameters(
        val iv: SerializableByteString?,
    ) : TestParameters {
        override fun toString(): String = "CipherParameters(iv.size=${iv?.size})"
    }

    override suspend fun CompatibilityTestScope<AES.CFB>.generate(isStressTest: Boolean) {
        val cipherIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val ivIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val parametersList = buildList {
            // size of IV = 16
            (List(ivIterations) { ByteString(CryptographyRandom.nextBytes(16)) } + listOf(null)).forEach { iv ->
                val parameters = CipherParameters(iv)
                val id = api.ciphers.saveParameters(parameters)
                add(id to parameters)
            }
        }

        generateKeys(isStressTest) { key, keyReference, _ ->
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
                            assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Initial Decrypt")
                            ciphertext
                        }
                        else -> {
                            val ciphertext = cipher.encryptWithIv(iv, plaintext)
                            logger.log { "ciphertext.size = ${ciphertext.size}" }
                            assertContentEquals(plaintext, cipher.decryptWithIv(iv, ciphertext), "Initial Decrypt")
                            ciphertext
                        }
                    }

                    api.ciphers.saveData(cipherParametersId, CipherData(keyReference, plaintext, ciphertext))
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<AES.CFB>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (iv), parametersId, _ ->
            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _, context ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher()
                    when (iv) {
                        null -> {
                            assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Decrypt from $context")
                            assertContentEquals(
                                plaintext, cipher.decrypt(cipher.encrypt(plaintext)),
                                "Encrypt-Decrypt from $context"
                            )
                        }
                        else -> {
                            assertContentEquals(plaintext, cipher.decryptWithIv(iv, ciphertext), "Decrypt from $context")
                            assertContentEquals(
                                plaintext, cipher.decryptWithIv(iv, cipher.encryptWithIv(iv, plaintext)),
                                "Encrypt-Decrypt from $context"
                            )
                        }
                    }
                }
            }
        }
    }
}
