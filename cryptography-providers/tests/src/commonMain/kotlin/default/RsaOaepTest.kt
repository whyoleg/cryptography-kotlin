/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlin.math.*
import kotlin.test.*

abstract class RsaOaepTest(provider: CryptographyProvider) : AlgorithmTest<RSA.OAEP>(RSA.OAEP, provider) {

    private suspend fun AlgorithmTestScope<RSA.OAEP>.encryptAndDecrypt(
        keyPair: RSA.OAEP.KeyPair,
        expectedSize: Int,
        plaintext: ByteArray,
        associatedData: ByteArray?,
    ) {
        if (!supportsAssociatedData(associatedData?.size)) return

        val encryptor = keyPair.publicKey.encryptor()
        val ciphertext = encryptor.encrypt(plaintext, associatedData)
        assertEquals(expectedSize, ciphertext.size)
        assertContentEquals(plaintext, keyPair.privateKey.decryptor().decrypt(ciphertext, associatedData))
    }

    @Test
    fun testSizes() = testWithAlgorithm {
        RsaKeySizes.forEach { keySize ->
            Digests.forEach { digest ->
                if (!supportsDigest(digest)) return@forEach

                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()

                if (supportsFormat(RSA.PublicKey.Format.DER)) {
                    assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeToByteString(RSA.PublicKey.Format.DER).size)
                }

                val maxSize = keySize.inBytes - 2 - 2 * digest.digestSize()

                encryptAndDecrypt(keyPair, keySize.inBytes, ByteArray(0), null)
                encryptAndDecrypt(keyPair, keySize.inBytes, ByteArray(0), ByteArray(0))
                encryptAndDecrypt(keyPair, keySize.inBytes, ByteArray(maxSize), null)
                encryptAndDecrypt(keyPair, keySize.inBytes, ByteArray(maxSize), ByteArray(0))

                repeat(8) { n ->
                    val size = 10.0.pow(n).toInt()
                    if (size < maxSize) {
                        val data = CryptographyRandom.nextBytes(size)
                        encryptAndDecrypt(keyPair, keySize.inBytes, data, null)
                        encryptAndDecrypt(keyPair, keySize.inBytes, data, ByteArray(0))
                        encryptAndDecrypt(keyPair, keySize.inBytes, data, data)
                    }
                }
            }
        }
    }
}
