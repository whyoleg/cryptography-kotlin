/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val maxPlaintextSize = 10000
private const val blockSize = 16 //for no padding

private fun Int.withPadding(padding: Boolean): Int = if (padding) this else this + blockSize - this % blockSize

abstract class AesCbcCompatibilityTest(provider: CryptographyProvider) :
    AesBasedCompatibilityTest<AES.CBC.Key, AES.CBC>(AES.CBC, provider) {

    @Serializable
    private data class CipherParameters(
        val padding: Boolean,
        val iv: ByteStringAsString?,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<AES.CBC>.generate(isStressTest: Boolean) {
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
                generateBoolean { padding ->
                    if (!supportsPadding(padding)) return@generateBoolean

                    val parameters = CipherParameters(padding, iv)
                    val id = api.ciphers.saveParameters(parameters)
                    add(id to parameters)
                }
            }
        }

        generateKeys(isStressTest) { key, keyReference, _ ->
            parametersList.forEach { (cipherParametersId, parameters) ->
                logger.log { "parameters = $parameters" }
                val cipher = key.cipher(parameters.padding)
                repeat(cipherIterations) {
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize).withPadding(parameters.padding)
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

    override suspend fun CompatibilityTestScope<AES.CBC>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (padding, iv), parametersId, _ ->
            if (!supportsPadding(padding)) return@getParameters

            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher(padding)
                    when (iv) {
                        null -> {
                            assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Decrypt")
                            assertContentEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext)), "Encrypt-Decrypt")
                        }
                        else -> {
                            assertContentEquals(plaintext, cipher.decryptWithIv(iv, ciphertext), "Decrypt")
                            assertContentEquals(plaintext, cipher.decryptWithIv(iv, cipher.encryptWithIv(iv, plaintext)), "Encrypt-Decrypt")
                        }
                    }
                }
            }
        }
    }
}
