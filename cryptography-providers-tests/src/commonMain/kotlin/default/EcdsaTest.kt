/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
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
    data class EcdsaSize(
        val curve: EC.Curve,
        val rawSignatureSize: Int,
        val derSignatureSizes: IntRange,
        val publicKeySize: Int,
        val privateKeySizes: List<Int>,
    )

    @Test
    fun testSizes() = testWithAlgorithm {
        listOf(
            // NIST curves
            EcdsaSize(EC.Curve.P256, 64, 68.rangeTo(72), 91, listOf(67, 138, 150)),
            EcdsaSize(EC.Curve.P384, 96, 100.rangeTo(104), 120, listOf(80, 185, 194)),
            EcdsaSize(EC.Curve.P521, 132, 136.rangeTo(139), 158, listOf(98, 241, 250)),

            // Note "private key sizes": smaller = openssl, larger = BouncyCastle

            // SECP256k1
            EcdsaSize(EC.Curve.secp256k1, 64, 68.rangeTo(72), 88, listOf(135, 144)),

            // Brainpool curves
            EcdsaSize(EC.Curve.brainpoolP256r1, 64, 68.rangeTo(72), 92, listOf(139, 152)),
            EcdsaSize(EC.Curve.brainpoolP384r1, 96, 100.rangeTo(104), 124, listOf(189, 202)),
            EcdsaSize(
                EC.Curve.brainpoolP512r1,
                128,
                132.rangeTo(139),
                158,
                listOf(239, 252)
            ) // Raw 128, DER sig slightly larger; PubKey ~154; PrivKey ~P521


        ).forEach { (curve, rawSignatureSize, derSignatureSizes, publicKeySize, privateKeySizes) ->
            if (!supportsCurve(curve)) {
                logger.log { "Skipping size test for unsupported curve: ${curve.name}" }
                return@forEach
            }

            logger.log { "\nRunning size test for curve: ${curve.name}" }
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            val actualPublicKeySize = keyPair.publicKey.encodeToByteString(EC.PublicKey.Format.DER).size
            logger.log { "Got ${curve.name} public key size: $actualPublicKeySize (expected $publicKeySize)" }
            assertEquals(
                publicKeySize,
                actualPublicKeySize,
                "Public key size mismatch for ${curve.name}, expected: $publicKeySize, but got $actualPublicKeySize"
            )
            val actualPrivateKeySize = keyPair.privateKey.encodeToByteString(EC.PrivateKey.Format.DER).size
                logger.log { "Got ${curve.name} private key size: $actualPrivateKeySize (allowed $privateKeySizes)" }
            assertContains(
                privateKeySizes,
                actualPrivateKeySize,
                "Private key size mismatch for ${curve.name}, expected one of $privateKeySizes, but got $actualPrivateKeySize"
            )

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
            if (!supportsCurve(curve)) {
                logger.log { "Skipping function test for unsupported curve: ${curve.name}" }
                return@forEach
            }
            logger.log { "Running function test for curve: ${curve.name}" }

            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            generateDigests { digest, _ ->
                if (!supportsDigest(digest)) {
                    logger.log { "Skipping digest $digest for curve ${curve.name}" }
                    return@generateDigests
                }

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
