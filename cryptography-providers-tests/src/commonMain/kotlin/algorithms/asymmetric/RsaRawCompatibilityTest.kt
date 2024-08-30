/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*

private fun ByteArray.pad(size: Int): ByteArray = ByteArray(size).also {
    copyInto(it, size - this.size)
}

abstract class RsaRawCompatibilityTest(provider: CryptographyProvider) :
    RsaBasedCompatibilityTest<RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair, RSA.RAW>(RSA.RAW, provider) {

    override suspend fun CompatibilityTestScope<RSA.RAW>.generate(isStressTest: Boolean) {
        val cipherIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val cipherParametersId = api.ciphers.saveParameters(TestParameters.Empty)
        generateKeys(isStressTest, singleDigest = SHA512) { keyPair, keyReference, keyParameters ->
            val maxPlaintextSize = keyParameters.keySizeBits.bits.inBytes
            logger.log { "maxPlaintextSize.size = $maxPlaintextSize" }
            val encryptor = keyPair.publicKey.encryptor()
            val decryptor = keyPair.privateKey.decryptor()

            repeat(cipherIterations) {
                // check both padded and not
                val plaintextSize = if (it % 2 == 0) CryptographyRandom.nextInt(maxPlaintextSize) else maxPlaintextSize - 1
                logger.log { "plaintext.size        = $plaintextSize" }
                // RSA RAW input should be equal to the key size;
                // some providers pad the value with zeroes, but it's not really correct
                val plaintext = ByteString(CryptographyRandom.nextBytes(plaintextSize).pad(maxPlaintextSize))
                logger.log { "plaintext             = ${Base64.encode(plaintext)}" }
                val ciphertext = encryptor.encrypt(plaintext)
                logger.log { "ciphertext.size       = ${ciphertext.size}" }
                logger.log { "ciphertext            = ${Base64.encode(ciphertext)}" }
                val reverse = decryptor.decrypt(ciphertext)
                logger.log { "reverse.size          = ${reverse.size}" }
                logger.log { "reverse               = ${Base64.encode(reverse)}" }

                assertContentEquals(plaintext, reverse, "Initial Decrypt")

                api.ciphers.saveData(cipherParametersId, CipherData(keyReference, plaintext, ciphertext))
            }
        }
    }

    override suspend fun CompatibilityTestScope<RSA.RAW>.validate() {
        val keyPairs = validateKeys()

        api.ciphers.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.ciphers.getData<CipherData>(parametersId) { (keyReference, plaintext, ciphertext), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val encryptors = publicKeys.map { it.encryptor() }
                val decryptors = privateKeys.map { it.decryptor() }

                decryptors.forEach { decryptor ->
                    assertContentEquals(plaintext, decryptor.decrypt(ciphertext), "Decrypt")

                    encryptors.forEach { encryptor ->
                        assertContentEquals(
                            plaintext,
                            decryptor.decrypt(encryptor.encrypt(plaintext)),
                            "Encrypt-Decrypt"
                        )
                    }
                }
            }
        }
    }
}
