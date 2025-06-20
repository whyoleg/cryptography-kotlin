/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val maxPlaintextSize = 10000
private const val maxAssociatedDataSize = 10000

abstract class AesGcmCompatibilityTest(provider: CryptographyProvider) :
    AesBasedCompatibilityTest<AES.GCM.Key, AES.GCM>(AES.GCM, provider) {

    @Serializable
    private data class CipherParameters(
        val tagSizeBits: Int,
        val iv: ByteStringAsString?,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<AES.GCM>.generate(isStressTest: Boolean) {
        val associatedDataIterations = when {
            isStressTest -> 10
            else -> 3
        }
        val cipherIterations = when {
            isStressTest -> 10
            else -> 3
        }
        val ivIterations = when {
            isStressTest -> 10
            else -> 3
        }

        val tagSizes = listOf(96, 128)
        val ivSizes = listOf(12, 16, null)

        val parametersList = buildList {
            tagSizes.forEach { tagSize ->
                if (!supportsTagSize(tagSize.bits)) return@forEach

                ivSizes.forEach { ivSize ->
                    repeat(ivIterations) {
                        val iv = ivSize?.let { ByteString(CryptographyRandom.nextBytes(it)) }
                        val parameters = CipherParameters(tagSize, iv)
                        val id = api.ciphers.saveParameters(parameters)
                        add(id to parameters)
                    }
                }
            }
        }

        generateKeys(isStressTest) { key, keyReference, _ ->
            parametersList.forEach { (cipherParametersId, parameters) ->
                logger.log { "parameters = $parameters" }
                val cipher = key.cipher(parameters.tagSizeBits.bits)
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
                                val ciphertext = cipher.resetIv(context).encryptWithIv(iv, plaintext, associatedData)
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

    override suspend fun CompatibilityTestScope<AES.GCM>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (tagSize, iv), parametersId, _ ->
            if (!supportsTagSize(tagSize.bits)) return@getParameters
            api.ciphers.getData<AuthenticatedCipherData>(parametersId) { (keyReference, associatedData, plaintext, ciphertext), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val cipher = key.cipher(tagSize.bits)

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
                                    cipher.resetIv(context).encryptWithIv(iv, plaintext, associatedData),
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
}

// GCM mode on JDK has a check which tries to prevent reuse of the same IV with the same key.
// we need to set random IV first to be able to reuse IV for different plaintext for the same key
private suspend fun AES.IvAuthenticatedCipher.resetIv(context: TestContext): AES.IvAuthenticatedCipher {
    if (context.provider.isJdk) encrypt(ByteString())
    return this
}
