/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.symmetric

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

abstract class AesEcbCompatibilityTest(provider: CryptographyProvider) :
    AesBasedCompatibilityTest<AES.ECB.Key, AES.ECB>(AES.ECB, provider) {

    @Serializable
    private data class CipherParameters(
        val padding: Boolean,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<AES.ECB>.generate(isStressTest: Boolean) {
        val cipherIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val parametersList = buildList {
            generateBoolean { padding ->
                val parameters = CipherParameters(padding)
                val id = api.ciphers.saveParameters(parameters)
                add(id to parameters)
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
                    val ciphertext = cipher.encrypt(plaintext)
                    logger.log { "ciphertext.size = ${ciphertext.size}" }
                    assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Initial Decrypt")

                    api.ciphers.saveData(cipherParametersId, CipherData(keyReference, plaintext, ciphertext))
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<AES.ECB>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (padding), parametersId, _ ->
            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher(padding)

                    assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Decrypt")
                    assertContentEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext)), "Encrypt-Decrypt")
                }
            }
        }
    }
}
