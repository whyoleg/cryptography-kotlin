/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.math.*
import kotlin.test.*

abstract class EdDsaTest(provider: CryptographyProvider) : AlgorithmTest<EdDSA>(EdDSA, provider), SignatureTest {

    data class EdDsaSize(
        val curve: EdDSA.Curve,
        val signatureSize: Int,
        val rawPublicKeySize: Int,
        val derPublicKeySize: Int,
        val rawPrivateKeySize: Int,
        // DER private key can have different sizes depending on whether the provider
        // includes the optional publicKey field (RFC 5958 OneAsymmetricKey)
        val derPrivateKeySizes: IntArray,
    )

    @Test
    fun testSizes() = testWithAlgorithm {
        listOf(
            EdDsaSize(
                curve = EdDSA.Curve.Ed25519,
                signatureSize = 64,
                rawPublicKeySize = 32,
                derPublicKeySize = 44,
                rawPrivateKeySize = 32,
                // 48 = basic PKCS#8, 83 = with publicKey field (RFC 5958)
                derPrivateKeySizes = intArrayOf(48, 83)
            ),
            EdDsaSize(
                curve = EdDSA.Curve.Ed448,
                signatureSize = 114,
                rawPublicKeySize = 57,
                derPublicKeySize = 69,
                rawPrivateKeySize = 57,
                // 73 = basic PKCS#8, 134 = with publicKey field (RFC 5958)
                derPrivateKeySizes = intArrayOf(73, 134)
            )
        ).forEach {
            val (
                curve,
                signatureSize,
                rawPublicKeySize,
                derPublicKeySize,
                rawPrivateKeySize,
                derPrivateKeySizes,
            ) = it

            if (!supportsCurve(curve)) return@forEach

            logger.log { "Running size test for curve: ${curve.name}" }
            val keyPair = algorithm.keyPairGenerator(curve).generateKey()

            suspend fun assertPublicKeySize(format: EdDSA.PublicKey.Format, expectedSize: Int) {
                if (supportsKeyFormat(format)) assertEquals(
                    expected = expectedSize,
                    actual = keyPair.publicKey.encodeToByteString(format).size,
                    message = "Public key ($format) size mismatch for ${curve.name}"
                )
            }

            suspend fun assertPrivateKeySize(format: EdDSA.PrivateKey.Format, expectedSize: Int) {
                if (supportsKeyFormat(format)) assertEquals(
                    expected = expectedSize,
                    actual = keyPair.privateKey.encodeToByteString(format).size,
                    message = "Private key ($format) size mismatch for ${curve.name}"
                )
            }

            suspend fun assertPrivateKeySizeOneOf(format: EdDSA.PrivateKey.Format, expectedSizes: IntArray) {
                if (supportsKeyFormat(format)) assertContains(
                    array = expectedSizes,
                    element = keyPair.privateKey.encodeToByteString(format).size,
                    message = "Private key ($format) size mismatch for ${curve.name}"
                )
            }

            assertPublicKeySize(EdDSA.PublicKey.Format.RAW, rawPublicKeySize)
            assertPublicKeySize(EdDSA.PublicKey.Format.DER, derPublicKeySize)

            assertPrivateKeySize(EdDSA.PrivateKey.Format.RAW, rawPrivateKeySize)
            assertPrivateKeySizeOneOf(EdDSA.PrivateKey.Format.DER, derPrivateKeySizes)

            val verifier = keyPair.publicKey.signatureVerifier()
            val generator = keyPair.privateKey.signatureGenerator()
            val sigEmpty = generator.generateSignature(ByteString())
            assertEquals(
                signatureSize,
                sigEmpty.size,
                "RAW signature size mismatch for empty data on ${curve.name}"
            )
            verifier.assertVerifySignature(
                ByteString(),
                sigEmpty,
                "RAW signature verification failed for empty data on ${curve.name}"
            )

            repeat(8) { n ->
                val size = 10.0.pow(n).toInt()
                val data = CryptographyRandom.nextBytes(size)
                val signature = generator.generateSignature(data)
                assertEquals(
                    signatureSize,
                    signature.size,
                    "RAW signature size mismatch for data size $size on ${curve.name}"
                )
                verifier.assertVerifySignature(
                    data,
                    signature,
                    "RAW signature verification failed for data size $size on ${curve.name}"
                )
            }
        }
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) {
            logger.log { "Skipping function test because functions are not supported by provider" }
            return@testWithAlgorithm
        }

        EdDSA.Curve.entries.forEach { curve ->
            if (!supportsCurve(curve)) return@forEach

            logger.log { "Running function test for curve: ${curve.name}" }

            val keyPair = algorithm.keyPairGenerator(curve).generateKey()
            val signatureGenerator = keyPair.privateKey.signatureGenerator()
            val signatureVerifier = keyPair.publicKey.signatureVerifier()

            repeat(10) {
                val size = CryptographyRandom.nextInt(1024, 20000) // Ensure non-trivial size
                val data = ByteString(CryptographyRandom.nextBytes(size))
                assertSignaturesViaFunction(signatureGenerator, signatureVerifier, data)
            }
        }
    }
}
