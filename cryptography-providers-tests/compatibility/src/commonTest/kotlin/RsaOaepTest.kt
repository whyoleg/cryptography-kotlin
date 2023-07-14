/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlin.test.*

private const val associatedDataIterations = 5
private const val cipherIterations = 5
private const val maxAssociatedDataSize = 10000

class RsaOaepTest : RsaBasedTest<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair, RSA.OAEP>(RSA.OAEP) {
    override suspend fun CompatibilityTestContext<RSA.OAEP>.generate() {
        val cipherParametersId = api.ciphers.saveParameters(TestParameters.Empty)
        generateKeys { keyPair, keyReference, keyParameters ->
            val maxPlaintextSize = keyParameters.keySizeBits.bits.inBytes - 2 - 2 * keyParameters.digestSizeBytes
            logger.log { "maxPlaintextSize.size = $maxPlaintextSize" }
            val encryptor = keyPair.publicKey.encryptor()
            val decryptor = keyPair.privateKey.decryptor()
            repeat(associatedDataIterations) { adIndex ->
                val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                logger.log { "associatedData.size   = $associatedDataSize" }
                val associatedData = associatedDataSize?.let(CryptographyRandom::nextBytes)
                repeat(cipherIterations) {
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                    logger.log { "plaintext.size        = $plaintextSize" }
                    val plaintext = CryptographyRandom.nextBytes(plaintextSize)
                    val ciphertext = encryptor.encrypt(plaintext, associatedData)
                    logger.log { "ciphertext.size       = ${ciphertext.size}" }

                    assertContentEquals(plaintext, decryptor.decrypt(ciphertext, associatedData), "Initial Decrypt")

                    api.ciphers.saveData(cipherParametersId, AuthenticatedCipherData(keyReference, associatedData, plaintext, ciphertext))
                }
            }
        }
    }

    override suspend fun CompatibilityTestContext<RSA.OAEP>.validate() {
        val keyPairs = validateKeys()

        api.ciphers.getParameters<TestParameters.Empty> { _, parametersId ->
            api.ciphers.getData<AuthenticatedCipherData>(parametersId) { (keyReference, associatedData, plaintext, ciphertext), _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val encryptors = publicKeys.map { it.encryptor() }
                val decryptors = privateKeys.map { it.decryptor() }

                decryptors.forEach { decryptor ->
                    assertContentEquals(plaintext, decryptor.decrypt(ciphertext, associatedData), "Decrypt")

                    encryptors.forEach { encryptor ->
                        assertContentEquals(
                            plaintext,
                            decryptor.decrypt(encryptor.encrypt(plaintext, associatedData), associatedData),
                            "Encrypt-Decrypt"
                        )
                    }
                }
            }
        }
    }
}
