/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class RsaPssTest {

    @Test
    fun testSizes() = runTestForEachAlgorithm(RSA.PSS) {
        generateRsaKeySizes { keySize ->
            generateDigests { digest, digestSize ->
                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()
                assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER).size)

                val maxSaltSize = (ceil((keySize.inBits - 1) / 8.0) - digestSize - 2).toInt()
                listOf(
                    0,
                    CryptographyRandom.nextInt(1, digestSize),
                    digestSize,
                    CryptographyRandom.nextInt(digestSize, maxSaltSize),
                    maxSaltSize
                ).forEach { saltSize ->
                    val signatureGenerator = keyPair.privateKey.signatureGenerator(saltSize.bytes)

                    assertEquals(keySize.inBytes, signatureGenerator.generateSignature(ByteArray(0)).size)
                    repeat(8) { n ->
                        val size = 10.0.pow(n).toInt()
                        val data = CryptographyRandom.nextBytes(size)
                        assertEquals(keySize.inBytes, signatureGenerator.generateSignature(data).size)
                    }
                }
            }
        }
    }
}
