/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
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
                    assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER).size)
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
        }
    }
}
