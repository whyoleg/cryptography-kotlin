/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.providers.tests.support.*
import dev.whyoleg.cryptography.random.*
import kotlinx.serialization.*
import kotlin.test.*

private const val cipherIterations = 5
private const val maxPlaintextSize = 10000
private const val blockSize = 16 //for no padding

private fun Int.withPadding(padding: Boolean): Int = if (padding) this else this + blockSize - this % blockSize

class AesCbcTest : AesBasedTest<AES.CBC.Key, AES.CBC>(AES.CBC) {

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

        generateKeys { key, keyReference, _ ->
            paddings.forEach { (cipherParametersId, padding) ->
                logger.log { "padding = $padding" }
                val cipher = key.cipher(padding)
                repeat(cipherIterations) {
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize).withPadding(padding)
                    logger.log { "plaintext.size  = $plaintextSize" }
                    val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                    val ciphertext = cipher.encrypt(plaintext)
                    logger.log { "ciphertext.size = ${ciphertext.size}" }

                    assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Initial Decrypt")

                    api.ciphers.saveData(cipherParametersId, CipherData(keyReference, plaintext, ciphertext))
                }
            }
        }
    }

    override suspend fun CompatibilityTestContext<AES.CBC>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (padding), parametersId ->
            if (!supportsPadding(padding)) return@getParameters

            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _ ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher(padding)
                    assertContentEquals(plaintext, cipher.decrypt(ciphertext), "Decrypt")
                    assertContentEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext)), "Encrypt-Decrypt")
                }
            }
        }
    }
}
