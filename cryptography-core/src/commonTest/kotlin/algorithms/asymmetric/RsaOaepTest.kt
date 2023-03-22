/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.*
import kotlin.math.*
import kotlin.test.*

class RsaOaepTest {

    private suspend fun RSA.OAEP.KeyPair.encryptAndDecrypt(expectedSize: Int, plaintext: ByteArray, associatedData: ByteArray?) {
        val encryptor = publicKey.encryptor()
        val ciphertext = encryptor.encrypt(plaintext, associatedData)
        assertEquals(expectedSize, ciphertext.size)
        assertContentEquals(plaintext, privateKey.decryptor().decrypt(ciphertext, associatedData))
    }

    @Test
    fun testSizes() = runTestForEachAlgorithm(RSA.OAEP) {
        generateRsaKeySizes { keySize ->
            generateDigests { digest, digestSize ->
                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()
                assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER).size)

                val maxSize = keySize.inBytes - 2 - 2 * digestSize

                keyPair.encryptAndDecrypt(keySize.inBytes, ByteArray(0), null)
                keyPair.encryptAndDecrypt(keySize.inBytes, ByteArray(0), ByteArray(0))
                keyPair.encryptAndDecrypt(keySize.inBytes, ByteArray(maxSize), null)
                keyPair.encryptAndDecrypt(keySize.inBytes, ByteArray(maxSize), ByteArray(0))

                repeat(8) { n ->
                    val size = 10.0.pow(n).toInt()
                    if (size < maxSize) {
                        val data = CryptographyRandom.Default.nextBytes(size)
                        keyPair.encryptAndDecrypt(keySize.inBytes, data, null)
                        keyPair.encryptAndDecrypt(keySize.inBytes, data, ByteArray(0))
                        keyPair.encryptAndDecrypt(keySize.inBytes, data, data)
                    }
                }
            }
        }
    }
}
