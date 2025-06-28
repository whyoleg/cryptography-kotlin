/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*
import kotlin.math.*
import kotlin.test.*

abstract class EcdsaTest(provider: CryptographyProvider) : AlgorithmTest<ECDSA>(ECDSA, provider), SignatureTest {

    //all sizes are in bytes
    // `privateKeySizes` contains three sizes.
    // depending on optional parameters:
    //  1. without parameters, without public key
    //  2. without parameters, with    public key
    //  3. with    parameters, with    public key
    @Suppress("ArrayInDataClass")
    data class EcdsaSize(
        val curve: EC.Curve,
        val rawSignatureSize: Int,
        val derSignatureSizes: IntRange,
        val rawCompressedPublicKeySize: Int = 0,
        val rawUncompressedPublicKeySize: Int = 0,
        val derPublicKeySize: Int,
        val rawPrivateKeySize: Int = 0,
        val derPrivateKeySizes: IntArray,
    )

    @Test
    fun testSizes() = testWithAlgorithm {
        listOf(
            // NIST curves
            EcdsaSize(
                curve = EC.Curve.P256,
                rawSignatureSize = 64,
                derSignatureSizes = 68.rangeTo(72),
                rawCompressedPublicKeySize = 33,
                rawUncompressedPublicKeySize = 65,
                derPublicKeySize = 91,
                rawPrivateKeySize = 32,
                derPrivateKeySizes = intArrayOf(67, 138, 150)
            ),
            EcdsaSize(
                curve = EC.Curve.P384,
                rawSignatureSize = 96,
                derSignatureSizes = 100.rangeTo(104),
                rawCompressedPublicKeySize = 49,
                rawUncompressedPublicKeySize = 97,
                derPublicKeySize = 120,
                rawPrivateKeySize = 48,
                derPrivateKeySizes = intArrayOf(80, 185, 194)
            ),
            EcdsaSize(
                curve = EC.Curve.P521,
                rawSignatureSize = 132,
                derSignatureSizes = 136.rangeTo(139),
                rawCompressedPublicKeySize = 67,
                rawUncompressedPublicKeySize = 133,
                derPublicKeySize = 158,
                rawPrivateKeySize = 66,
                derPrivateKeySizes = intArrayOf(98, 241, 250)
            ),

            // Note "private key sizes": smaller = openssl, larger = BouncyCastle

            // SECP256k1
            EcdsaSize(
                curve = EC.Curve.secp256k1,
                rawSignatureSize = 64,
                derSignatureSizes = 68.rangeTo(72),
                rawCompressedPublicKeySize = 33,
                rawUncompressedPublicKeySize = 65,
                derPublicKeySize = 88,
                rawPrivateKeySize = 32,
                derPrivateKeySizes = intArrayOf(135, 144)
            ),

            // Brainpool curves
            EcdsaSize(
                curve = EC.Curve.brainpoolP256r1,
                rawSignatureSize = 64,
                derSignatureSizes = 68.rangeTo(72),
                rawCompressedPublicKeySize = 33,
                rawUncompressedPublicKeySize = 65,
                derPublicKeySize = 92,
                rawPrivateKeySize = 32,
                derPrivateKeySizes = intArrayOf(139, 152)
            ),
            EcdsaSize(
                curve = EC.Curve.brainpoolP384r1,
                rawSignatureSize = 96,
                derSignatureSizes = 100.rangeTo(104),
                rawCompressedPublicKeySize = 49,
                rawUncompressedPublicKeySize = 97,
                derPublicKeySize = 124,
                rawPrivateKeySize = 48,
                derPrivateKeySizes = intArrayOf(189, 202)
            ),
            EcdsaSize(
                curve = EC.Curve.brainpoolP512r1,
                rawSignatureSize = 128,
                derSignatureSizes = 132.rangeTo(139),
                rawCompressedPublicKeySize = 65,
                rawUncompressedPublicKeySize = 129,
                derPublicKeySize = 158,
                rawPrivateKeySize = 64,
                derPrivateKeySizes = intArrayOf(239, 252)
            ) // Raw 128, DER sig slightly larger; PubKey ~154; PrivKey ~P521
        ).forEach {
            val (
                curve,
                rawSignatureSize,
                derSignatureSizes,
                rawCompressedPublicKeySize,
                rawUncompressedPublicKeySize,
                derPublicKeySize,
                rawPrivateKeySize,
                rawPrivateKeySizes,
            ) = it

            if (!supportsCurve(curve)) return@forEach

            logger.log { "Running size test for curve: ${curve.name}" }
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            suspend fun assertPublicKeySize(format: EC.PublicKey.Format, expectedSize: Int) {
                if (supportsKeyFormat(format)) assertEquals(
                    expected = expectedSize,
                    actual = keyPair.publicKey.encodeToByteString(format).size,
                    message = "Public key ($format) size mismatch for ${curve.name}"
                )
            }

            suspend fun assertPrivateKeySize(format: EC.PrivateKey.Format, expectedSizes: IntArray) {
                if (supportsKeyFormat(format)) assertContains(
                    array = expectedSizes,
                    element = keyPair.privateKey.encodeToByteString(format).size,
                    message = "Private key ($format) size mismatch for ${curve.name}"
                )
            }

            assertPublicKeySize(EC.PublicKey.Format.DER, derPublicKeySize)
            assertPublicKeySize(EC.PublicKey.Format.RAW.Compressed, rawCompressedPublicKeySize)
            assertPublicKeySize(EC.PublicKey.Format.RAW.Uncompressed, rawUncompressedPublicKeySize)

            assertPrivateKeySize(EC.PrivateKey.Format.RAW, intArrayOf(rawPrivateKeySize))
            assertPrivateKeySize(EC.PrivateKey.Format.DER, rawPrivateKeySizes)

            generateDigests { digest, _ ->
                if (!supportsDigest(digest)) {
                    logger.log { "Skipping digest $digest for curve ${curve.name}" }
                    return@generateDigests
                }

                // RAW signature
                run {
                    val verifier = keyPair.publicKey.signatureVerifier(digest, ECDSA.SignatureFormat.RAW)
                    keyPair.privateKey.signatureGenerator(digest, ECDSA.SignatureFormat.RAW).run {
                        val sigEmpty = generateSignature(ByteArray(0))
                        assertEquals(
                            rawSignatureSize,
                            sigEmpty.size,
                            "RAW signature size mismatch for empty data on ${curve.name} / ${digest.name}"
                        )
                        assertTrue(
                            verifier.tryVerifySignature(ByteArray(0), sigEmpty),
                            "RAW signature verification failed for empty data on ${curve.name} / ${digest.name}"
                        )

                        repeat(8) { n ->
                            val size = 10.0.pow(n).toInt()
                            val data = CryptographyRandom.nextBytes(size)
                            val signature = generateSignature(data)
                            assertEquals(
                                rawSignatureSize,
                                signature.size,
                                "RAW signature size mismatch for data size $size on ${curve.name} / ${digest.name}"
                            )
                            assertTrue(
                                verifier.tryVerifySignature(data, signature),
                                "RAW signature verification failed for data size $size on ${curve.name} / ${digest.name}"
                            )
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

                            assertContains(
                                derSignatureSizes, signature.size, "DER signature size mismatch on ${curve.name} / ${digest.name}. " +
                                        "Expected one of $derSignatureSizes, got ${signature.size}. " +
                                        "Signature (Base64): ${Base64.encode(signature)}"
                            )
                        }

                        assertSignatureSize(generateSignature(ByteArray(0)))
                        repeat(8) { n ->
                            val size = 10.0.pow(n).toInt()
                            val data = CryptographyRandom.nextBytes(size)
                            val signature = generateSignature(data)
                            assertSignatureSize(signature)
                            assertTrue(
                                verifier.tryVerifySignature(data, signature),
                                "DER signature verification failed for data size $size on ${curve.name} / ${digest.name}"
                            )
                        }
                    }
                }
            }
        }
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) {
            logger.log { "Skipping function test because functions are not supported by provider" }
            return@testWithAlgorithm
        }

        listOf(
            EC.Curve.P256,
            EC.Curve.P384,
            EC.Curve.P521,
            EC.Curve.secp256k1,
            EC.Curve.brainpoolP256r1,
            EC.Curve.brainpoolP384r1,
            EC.Curve.brainpoolP512r1,
        ).forEach { curve ->
            if (!supportsCurve(curve)) return@forEach

            logger.log { "Running function test for curve: ${curve.name}" }

            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            generateDigests { digest, _ ->
                if (!supportsDigest(digest)) return@generateDigests

                ECDSA.SignatureFormat.entries.forEach { format ->
                    logger.log { "Testing format $format for ${curve.name} / ${digest.name}" }
                    val signatureGenerator = keyPair.privateKey.signatureGenerator(digest, format)
                    val signatureVerifier = keyPair.publicKey.signatureVerifier(digest, format)

                    repeat(10) {
                        val size = CryptographyRandom.nextInt(1024, 20000) // Ensure non-trivial size
                        val data = ByteString(CryptographyRandom.nextBytes(size))
                        assertSignaturesViaFunction(signatureGenerator, signatureVerifier, data)
                    }
                }
            }
        }
    }
}
