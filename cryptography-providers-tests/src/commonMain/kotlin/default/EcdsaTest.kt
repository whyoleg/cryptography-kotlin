/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlin.io.encoding.*
import kotlin.math.*
import kotlin.test.*

abstract class EcdsaTest(provider: CryptographyProvider) : ProviderTest(provider) {

    //all sizes are in bytes
    // `privateKeySizes` contains three sizes.
    // depending on optional parameters:
    //  1. without parameters, without public key
    //  2. without parameters, with    public key
    //  3. with    parameters, with    public key
    data class EcdsaSize(
        val curve: EC.Curve,
        val rawSignatureSize: Int,
        val derSignatureSizes: List<Int>,
        val publicKeySize: Int,
        val privateKeySizes: List<Int>,
    )

    @Test
    fun testSizes() = testAlgorithm(ECDSA) {
        listOf(
            EcdsaSize(EC.Curve.P256, 64, listOf(68, 69, 70, 71, 72), 91, listOf(67, 138, 150)),
            EcdsaSize(EC.Curve.P384, 96, listOf(100, 101, 102, 103, 104), 120, listOf(80, 185, 194)),
            EcdsaSize(EC.Curve.P521, 132, listOf(136, 137, 138, 139), 158, listOf(98, 241, 250)),
            EcdsaSize(EC.Curve("secp256k1"), 64, listOf(68, 69, 70, 71, 72), 88, listOf(135, 144)),
        ).forEach { (curve, rawSignatureSize, derSignatureSizes, publicKeySize, privateKeySizes) ->
            if (!supportsCurve(curve)) return@forEach

            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            assertEquals(publicKeySize, keyPair.publicKey.encodeToByteString(EC.PublicKey.Format.DER).size)
            assertContains(privateKeySizes, keyPair.privateKey.encodeToByteString(EC.PrivateKey.Format.DER).size)

            generateDigests { digest, _ ->
                if (!supportsDigest(digest)) return@generateDigests

                // RAW signature
                run {
                    val verifier = keyPair.publicKey.signatureVerifier(digest, ECDSA.SignatureFormat.RAW)
                    keyPair.privateKey.signatureGenerator(digest, ECDSA.SignatureFormat.RAW).run {
                        assertEquals(rawSignatureSize, generateSignature(ByteArray(0)).size)
                        repeat(8) { n ->
                            val size = 10.0.pow(n).toInt()
                            val data = CryptographyRandom.nextBytes(size)
                            val signature = generateSignature(data)
                            assertEquals(rawSignatureSize, signature.size)
                            assertTrue(verifier.tryVerifySignature(data, signature))
                        }
                    }
                }
                // DER signature
                run {
                    val verifier = keyPair.publicKey.signatureVerifier(digest, ECDSA.SignatureFormat.DER)
                    keyPair.privateKey.signatureGenerator(digest, ECDSA.SignatureFormat.DER).run {
                        fun assertSignatureSize(signature: ByteArray) {
                            if (signature.size in derSignatureSizes) return
                            // enhance a message with Base64 encoded signature
                            assertContains(derSignatureSizes, signature.size, "DER: ${Base64.encode(signature)}")
                        }

                        assertSignatureSize(generateSignature(ByteArray(0)))
                        repeat(8) { n ->
                            val size = 10.0.pow(n).toInt()
                            val data = CryptographyRandom.nextBytes(size)
                            val signature = generateSignature(data)
                            assertSignatureSize(signature)
                            assertTrue(verifier.tryVerifySignature(data, signature))
                        }
                    }
                }
            }
        }
    }
}
