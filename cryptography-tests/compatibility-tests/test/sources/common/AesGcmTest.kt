package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val associatedDataIterations = 5
private const val cipherIterations = 10
private const val maxPlaintextSize = 10000
private const val maxAssociatedDataSize = 10000

class AesGcmTest : AesBasedTest<AES.GCM.Key, AES.GCM>(AES.GCM) {

    @Serializable
    private data class CipherParameters(val tagSizeBits: Int) : TestParameters

    override suspend fun CompatibilityTestContext<AES.GCM>.generate() {
        val tagSizes = listOf(96, 104, 112, 120, 128).map { tagSizeBits ->
            val id = api.ciphers.saveParameters(CipherParameters(tagSizeBits))
            id to tagSizeBits.bits
        }

        generateKeys { key, keyReference, keyParameters ->
            tagSizes.forEach { (cipherParametersId, tagSize) ->
                logger.log { "tagSize = $tagSize" }
                val cipher = key.cipher(tagSize)
                repeat(associatedDataIterations) { adIndex ->
                    val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                    logger.log { "associatedData.size = $associatedDataSize" }
                    val associatedData = associatedDataSize?.let(CryptographyRandom::nextBytes)
                    repeat(cipherIterations) {
                        val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                        logger.log { "plaintext.size      = $plaintextSize" }
                        val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                        val ciphertext = cipher.encrypt(plaintext, associatedData)
                        logger.log { "ciphertext.size     = ${ciphertext.size}" }

                        assertContentEquals(plaintext, cipher.decrypt(ciphertext, associatedData), "Initial Decrypt")

                        api.ciphers.saveData(
                            cipherParametersId,
                            AuthenticatedCipherData(keyReference, associatedData, plaintext, ciphertext)
                        )
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestContext<AES.GCM>.validate() {
        val keys = validateKeys()

        api.ciphers.getParameters<CipherParameters> { (tagSize), parametersId ->
            api.ciphers.getData<AuthenticatedCipherData>(parametersId) { (keyReference, associatedData, plaintext, ciphertext), _ ->
                keys.getValue(keyReference).forEach { key ->
                    val cipher = key.cipher(tagSize.bits)
                    assertContentEquals(plaintext, cipher.decrypt(ciphertext, associatedData), "Decrypt")
                    assertContentEquals(
                        plaintext,
                        cipher.decrypt(cipher.encrypt(plaintext, associatedData), associatedData),
                        "Encrypt-Decrypt"
                    )
                }
            }
        }
    }
}
