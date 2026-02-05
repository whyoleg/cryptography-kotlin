/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.math.*
import kotlin.test.*

abstract class RsaPssTest(provider: CryptographyProvider) : AlgorithmTest<RSA.PSS>(RSA.PSS, provider), SignatureTest {

    @Test
    fun testSizes() = testWithAlgorithm {
        RsaKeySizes.forEach { keySize ->
            Digests.forEach { digest ->
                if (!supportsDigest(digest)) return@forEach
                val digestSize = digest.digestSize()
                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()

                if (supportsFormat(RSA.PublicKey.Format.DER)) {
                    assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeToByteString(RSA.PublicKey.Format.DER).size)
                }

                val maxSaltSize = (ceil((keySize.inBits - 1) / 8.0) - digestSize - 2).toInt()
                listOf(
                    null,
                    0,
                    CryptographyRandom.nextInt(1, digestSize),
                    digestSize,
                    CryptographyRandom.nextInt(digestSize, maxSaltSize),
                    maxSaltSize
                ).forEach { saltSize ->
                    if (!supportsSaltSize(saltSize)) return@forEach

                    val (signatureGenerator, signatureVerifier) = when (saltSize) {
                        null -> keyPair.privateKey.signatureGenerator() to keyPair.publicKey.signatureVerifier()
                        else -> keyPair.privateKey.signatureGenerator(saltSize.bytes) to keyPair.publicKey.signatureVerifier(saltSize.bytes)
                    }

                    assertEquals(keySize.inBytes, signatureGenerator.generateSignature(ByteArray(0)).size)
                    repeat(8) { n ->
                        val size = 10.0.pow(n).toInt()
                        val data = CryptographyRandom.nextBytes(size)
                        val signature = signatureGenerator.generateSignature(data)
                        assertEquals(keySize.inBytes, signature.size)
                        signatureVerifier.assertVerifySignature(data, signature)
                    }
                }
            }
        }
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) return@testWithAlgorithm

        RsaKeySizes.forEach { keySize ->
            Digests.forEach { digest ->
                if (!supportsDigest(digest)) return@forEach

                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()
                val signatureGenerator = keyPair.privateKey.signatureGenerator()
                val signatureVerifier = keyPair.publicKey.signatureVerifier()

                repeat(5) {
                    val size = CryptographyRandom.nextInt(20000)
                    val data = ByteString(CryptographyRandom.nextBytes(size))
                    assertSignaturesViaFunction(signatureGenerator, signatureVerifier, data)
                }
            }
        }
    }
}
