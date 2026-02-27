/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.math.*
import kotlin.test.*

abstract class DsaTest(provider: CryptographyProvider) : AlgorithmTest<DSA>(DSA, provider), SignatureTest {

    private data class DsaCase(
        val digest: CryptographyAlgorithmId<Digest>,
        val keySize: BinarySize,
    )

    private val cases = listOf(
        DsaCase(digest = SHA1, keySize = 1024.bits),
        DsaCase(digest = SHA256, keySize = 2048.bits),
    )

    @Test
    fun testSignVerifyAndEncodeDecode_der_pem() = testWithAlgorithm {
        val publicKeyFormats = listOf(
            DSA.PublicKey.Format.DER,
            DSA.PublicKey.Format.PEM,
        )
        val privateKeyFormats = listOf(
            DSA.PrivateKey.Format.DER,
            DSA.PrivateKey.Format.PEM,
        )

        cases.forEach { (digest, keySize) ->
            if (!supportsDigest(digest)) return@forEach

            logger.log { "Testing DSA with digest=${digest.name}, keySize=${keySize.inBits}" }

            val keyPair = algorithm.keyPairGenerator(keySize).generateKey()

            publicKeyFormats.forEach { format ->
                if (!supportsFormat(format)) return@forEach
                val bytes = keyPair.publicKey.encodeToByteString(format)
                val decoded = algorithm.publicKeyDecoder().decodeFromByteString(format, bytes)
                assertContentEquals(bytes, decoded.encodeToByteString(format), "Public key encode/decode mismatch for $format")
            }

            privateKeyFormats.forEach { format ->
                if (!supportsFormat(format)) return@forEach
                val bytes = keyPair.privateKey.encodeToByteString(format)
                val decoded = algorithm.privateKeyDecoder().decodeFromByteString(format, bytes)
                assertContentEquals(bytes, decoded.encodeToByteString(format), "Private key encode/decode mismatch for $format")
            }

            val signatureGenerator = keyPair.privateKey.signatureGenerator(digest, DSA.SignatureFormat.DER)
            val signatureVerifier = keyPair.publicKey.signatureVerifier(digest, DSA.SignatureFormat.DER)

            run {
                val data = ByteString()
                val signature = signatureGenerator.generateSignature(data)
                signatureVerifier.assertVerifySignature(data, signature, "DSA verify failed for empty data ($digest)")
            }

            repeat(8) { n ->
                val size = 10.0.pow(n).toInt()
                val data = ByteString(CryptographyRandom.nextBytes(size))
                val signature = signatureGenerator.generateSignature(data)
                signatureVerifier.assertVerifySignature(data, signature, "DSA verify failed for size=$size ($digest)")
            }
        }
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) {
            logger.log { "Skipping function test because functions are not supported by provider" }
            return@testWithAlgorithm
        }

        cases.forEach { (digest, keySize) ->
            if (!supportsDigest(digest)) return@forEach

            logger.log { "Testing DSA functions with digest=${digest.name}, keySize=${keySize.inBits}" }

            val keyPair = algorithm.keyPairGenerator(keySize).generateKey()

            val signatureGenerator = keyPair.privateKey.signatureGenerator(digest, DSA.SignatureFormat.DER)
            val signatureVerifier = keyPair.publicKey.signatureVerifier(digest, DSA.SignatureFormat.DER)

            repeat(10) {
                val size = CryptographyRandom.nextInt(1024, 20000)
                val data = ByteString(CryptographyRandom.nextBytes(size))
                assertSignaturesViaFunction(signatureGenerator, signatureVerifier, data)
            }
        }
    }
}
