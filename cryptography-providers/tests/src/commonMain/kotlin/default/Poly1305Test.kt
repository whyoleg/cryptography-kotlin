/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

@OptIn(DelicateCryptographyApi::class)
abstract class Poly1305Test(provider: CryptographyProvider) : AlgorithmTest<Poly1305>(Poly1305, provider) {

    @Test
    fun testKeySize() = testWithAlgorithm {
        // Poly1305 uses 32-byte one-time keys
        assertEquals(32, Poly1305.KEY_SIZE, "Poly1305 key size constant mismatch")
    }

    @Test
    fun testTagSize() = testWithAlgorithm {
        // Poly1305 produces 16-byte (128-bit) tags
        assertEquals(16, Poly1305.TAG_SIZE, "Poly1305 tag size constant mismatch")
    }

    @Test
    fun testTagGeneration() = testWithAlgorithm {
        val keyBytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, keyBytes)

        listOf(0, 1, 15, 16, 17, 64, 100, 1000).forEach { size ->
            val message = CryptographyRandom.nextBytes(size)
            val tag = key.signatureGenerator().generateSignature(message)

            assertEquals(
                Poly1305.TAG_SIZE,
                tag.size,
                "Tag size mismatch for message size $size"
            )
        }
    }

    @Test
    fun testTagVerification() = testWithAlgorithm {
        val keyBytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, keyBytes)

        val message = CryptographyRandom.nextBytes(100)
        val tag = key.signatureGenerator().generateSignature(message)

        assertTrue(
            key.signatureVerifier().tryVerifySignature(message, tag),
            "Tag verification failed"
        )
    }

    @Test
    fun testTagVerificationFailsWithWrongMessage() = testWithAlgorithm {
        val keyBytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, keyBytes)

        val message = CryptographyRandom.nextBytes(100)
        val tag = key.signatureGenerator().generateSignature(message)

        // Modify message
        val wrongMessage = message.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }

        assertFalse(
            key.signatureVerifier().tryVerifySignature(wrongMessage, tag),
            "Tag verification should fail with wrong message"
        )
    }

    @Test
    fun testTagVerificationFailsWithWrongTag() = testWithAlgorithm {
        val keyBytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, keyBytes)

        val message = CryptographyRandom.nextBytes(100)
        val tag = key.signatureGenerator().generateSignature(message)

        // Modify tag
        val wrongTag = tag.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }

        assertFalse(
            key.signatureVerifier().tryVerifySignature(message, wrongTag),
            "Tag verification should fail with wrong tag"
        )
    }

    @Test
    fun testDifferentKeysProduceDifferentTags() = testWithAlgorithm {
        val key1Bytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key2Bytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)

        val key1 = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, key1Bytes)
        val key2 = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, key2Bytes)

        val message = CryptographyRandom.nextBytes(100)

        val tag1 = key1.signatureGenerator().generateSignature(message)
        val tag2 = key2.signatureGenerator().generateSignature(message)

        assertFalse(
            tag1.contentEquals(tag2),
            "Different keys should produce different tags"
        )
    }

    @Test
    fun testKeyRoundTrip() = testWithAlgorithm {
        val keyBytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, keyBytes)

        val encodedKey = key.encodeToByteArray(Poly1305.Key.Format.RAW)
        assertContentEquals(keyBytes, encodedKey, "Key round-trip failed")
    }

    @Test
    fun testDeterministicTagGeneration() = testWithAlgorithm {
        val keyBytes = CryptographyRandom.nextBytes(Poly1305.KEY_SIZE)
        val key = algorithm.keyDecoder().decodeFromByteArray(Poly1305.Key.Format.RAW, keyBytes)

        val message = CryptographyRandom.nextBytes(100)

        // Same key + same message should produce same tag
        val tag1 = key.signatureGenerator().generateSignature(message)
        val tag2 = key.signatureGenerator().generateSignature(message)

        assertContentEquals(
            tag1,
            tag2,
            "Same key and message should produce same tag"
        )
    }

    // RFC 7539 Section 2.5.2 Test Vector
    // https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.2
    private data class Poly1305TestVector(
        val key: String,     // hex, 32 bytes
        val message: String, // hex or ASCII
        val tag: String,     // hex, 16 bytes
    )

    private val rfcTestVectors = listOf(
        // RFC 7539 Section 2.5.2
        Poly1305TestVector(
            key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
            message = "43727970746f6772617068696320466f72756d2052657365617263682047726f7570", // "Cryptographic Forum Research Group"
            tag = "a8061dc1305136c6c22b8baf0c0127a9"
        ),
    )

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc7539TagGeneration() = testWithAlgorithm {
        for ((index, vector) in rfcTestVectors.withIndex()) {
            val key = algorithm.keyDecoder().decodeFromByteArray(
                Poly1305.Key.Format.RAW,
                vector.key.hexToByteArray()
            )
            val message = vector.message.hexToByteArray()
            val expectedTag = vector.tag.hexToByteArray()

            val tag = key.signatureGenerator().generateSignature(message)

            assertContentEquals(
                expectedTag,
                tag,
                "RFC 7539 test vector ${index + 1} tag mismatch"
            )
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc7539TagVerification() = testWithAlgorithm {
        for ((index, vector) in rfcTestVectors.withIndex()) {
            val key = algorithm.keyDecoder().decodeFromByteArray(
                Poly1305.Key.Format.RAW,
                vector.key.hexToByteArray()
            )
            val message = vector.message.hexToByteArray()
            val tag = vector.tag.hexToByteArray()

            assertTrue(
                key.signatureVerifier().tryVerifySignature(message, tag),
                "RFC 7539 test vector ${index + 1} verification failed"
            )
        }
    }

    // Additional test vectors from various sources
    private val additionalTestVectors = listOf(
        // Empty message
        Poly1305TestVector(
            key = "00000000000000000000000000000000" + "00000000000000000000000000000000",
            message = "",
            tag = "00000000000000000000000000000000"
        ),
        // All zeros with non-zero key
        Poly1305TestVector(
            key = "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
            message = "0000000000000000000000000000000000000000000000000000000000000000",
            tag = "49ec78090e481ec6c26b33b91ccc0307"
        ),
    )

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testAdditionalVectors() = testWithAlgorithm {
        for ((index, vector) in additionalTestVectors.withIndex()) {
            val key = algorithm.keyDecoder().decodeFromByteArray(
                Poly1305.Key.Format.RAW,
                vector.key.hexToByteArray()
            )
            val message = vector.message.hexToByteArray()
            val expectedTag = vector.tag.hexToByteArray()

            val tag = key.signatureGenerator().generateSignature(message)

            assertContentEquals(
                expectedTag,
                tag,
                "Additional test vector ${index + 1} tag mismatch"
            )

            assertTrue(
                key.signatureVerifier().tryVerifySignature(message, tag),
                "Additional test vector ${index + 1} verification failed"
            )
        }
    }
}