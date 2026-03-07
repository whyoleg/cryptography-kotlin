/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*

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
            val encryptor2 = keyPair.privateKey.getPublicKey().encryptor()
            val decryptor = keyPair.privateKey.decryptor()
            repeat(associatedDataIterations) { adIndex ->
                val associatedDataSize = if (adIndex == 0) null else CryptographyRandom.nextInt(maxAssociatedDataSize)
                if (!supportsAssociatedData(associatedDataSize)) return@repeat

                logger.log { "associatedData.size   = $associatedDataSize" }
                val associatedData = associatedDataSize?.let(CryptographyRandom::nextBytes)?.let(::ByteString)
                repeat(cipherIterations) {
                    val plaintextSize = CryptographyRandom.nextInt(maxPlaintextSize)
                    logger.log { "plaintext.size        = $plaintextSize" }
                    if (!supportsDataInput(plaintextSize)) return@repeat
                    val plaintext = ByteString(CryptographyRandom.nextBytes(plaintextSize))
                    val ciphertext = encryptor.encrypt(plaintext, associatedData)
                    val ciphertext2 = encryptor2.encrypt(plaintext, associatedData)
                    logger.log { "ciphertext.size       = ${ciphertext.size}" }
                    logger.log { "ciphertext2.size       = ${ciphertext2.size}" }

                    assertContentEquals(plaintext, decryptor.decrypt(ciphertext, associatedData), "Initial Decrypt")
                    assertContentEquals(plaintext, decryptor.decrypt(ciphertext2, associatedData), "Initial Decrypt")

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
                val encryptors2 = privateKeys.map { it.getPublicKey().encryptor() }

                decryptors.forEach { decryptor ->
                    assertContentEquals(plaintext, decryptor.decrypt(ciphertext, associatedData), "Decrypt")

                    encryptors.forEach { encryptor ->
                        assertContentEquals(
                            plaintext,
                            decryptor.decrypt(encryptor.encrypt(plaintext, associatedData), associatedData),
                            "Encrypt-Decrypt"
                        )
                    }
                    encryptors2.forEach { encryptor ->
                        assertContentEquals(
                            plaintext,
                            decryptor.decrypt(encryptor.encrypt(plaintext, associatedData), associatedData),
                            "Encrypt-Decrypt via PrivateKey.getPublicKey"
                        )
                    }
                }
            }
        }
    }
}
