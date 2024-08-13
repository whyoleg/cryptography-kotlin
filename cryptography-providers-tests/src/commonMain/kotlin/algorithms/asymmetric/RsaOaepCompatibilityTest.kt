/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.binary.BinarySize.Companion.bits
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

private const val maxAssociatedDataSize = 10000

abstract class RsaOaepCompatibilityTest(provider: CryptographyProvider) :
    RsaBasedCompatibilityTest<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair, RSA.OAEP>(RSA.OAEP, provider) {

    override suspend fun CompatibilityTestScope<RSA.OAEP>.generate(isStressTest: Boolean) {
        val associatedDataIterations = when {
            isStressTest -> 5
            else         -> 2
        }
        val cipherIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        val cipherParametersId = api.ciphers.saveParameters(TestParameters.Empty)
        generateKeys(isStressTest) { keyPair, keyReference, keyParameters ->
            val maxPlaintextSize = keyParameters.keySizeBits.bits.inBytes - 2 - 2 * keyParameters.digestSizeBytes
            logger.log { "maxPlaintextSize.size = $maxPlaintextSize" }
            val encryptor = keyPair.publicKey.encryptor()
            val decryptor = keyPair.privateKey.decryptor()
            repeat(associatedDataIterations) { adIndex ->
                val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                if (!supportsAssociatedData(associatedDataSize)) return@repeat

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

    override suspend fun CompatibilityTestScope<RSA.OAEP>.validate() {
        val keyPairs = validateKeys()

        api.ciphers.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.ciphers.getData<AuthenticatedCipherData>(parametersId) { (keyReference, associatedData, plaintext, ciphertext), _, _ ->
                if (!supportsAssociatedData(associatedData?.size)) return@getData

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
