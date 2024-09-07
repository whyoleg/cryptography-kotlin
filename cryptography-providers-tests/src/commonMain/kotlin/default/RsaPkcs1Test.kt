/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlin.math.*
import kotlin.test.*

abstract class RsaPkcs1Test(provider: CryptographyProvider) : ProviderTest(provider) {

    @Test
    fun testSizes() = testAlgorithm(RSA.PKCS1) {
        generateRsaKeySizes { keySize ->
            generateDigests { digest, _ ->
                if (!supportsDigest(digest)) return@generateDigests

                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()

                if (supportsKeyFormat(RSA.PublicKey.Format.DER)) {
                    assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeToByteString(RSA.PublicKey.Format.DER).size)
                }

                val signatureGenerator = keyPair.privateKey.signatureGenerator()
                val signatureVerifier = keyPair.publicKey.signatureVerifier()

                assertEquals(keySize.inBytes, signatureGenerator.generateSignature(ByteArray(0)).size)
                repeat(8) { n ->
                    val size = 10.0.pow(n).toInt()
                    val data = CryptographyRandom.nextBytes(size)
                    val signature = signatureGenerator.generateSignature(data)
                    assertEquals(keySize.inBytes, signature.size)
                    assertTrue(signatureVerifier.verifySignature(data, signature))
                }
            }

            if (supportsEncryption()) {
                // digest is not used for encryption
                val keyPair = algorithm.keyPairGenerator(keySize, SHA1).generateKey()

                val maxSize = keySize.inBytes - 11 // PKCS1 padding

                encryptAndDecrypt(keyPair, keySize.inBytes, ByteArray(maxSize))

                repeat(4) { n ->
                    val size = 10.0.pow(n).toInt()
                    if (size < maxSize) {
                        println(size)
                        val data = CryptographyRandom.nextBytes(size)
                        encryptAndDecrypt(keyPair, keySize.inBytes, data)
                    }
                }
            }
        }
    }

    private suspend fun encryptAndDecrypt(
        keyPair: RSA.PKCS1.KeyPair,
        expectedSize: Int,
        plaintext: ByteArray,
    ) {
        val encryptor = keyPair.publicKey.encryptor()
        val decryptor = keyPair.privateKey.decryptor()
        val ciphertext = encryptor.encrypt(plaintext)
        assertEquals(expectedSize, ciphertext.size, "plaintext size: ${plaintext.size}")
        assertContentEquals(plaintext, decryptor.decrypt(ciphertext))
    }

}
