/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlinx.io.bytestring.*
import kotlin.test.*

abstract class ScryptTest(provider: CryptographyProvider) : AlgorithmTest<Scrypt>(Scrypt, provider) {
    @Test
    fun byteStringSaltOverload() = testWithAlgorithm {
        val derivation = algorithm.secretDerivation(
            cost = 16,
            blockSize = 1,
            parallelization = 1,
            outputSize = 64.bytes,
            salt = ByteString(ByteArray(0)),
            maximumMemoryBytes = 2816,
        )
        assertEquals(
            "77d6576238657b203b19ca42c18a0497" +
                    "f16b4844e3074ae8dfdffa3fede21442" +
                    "fcd0069ded0948f8326a753a0fc81f17" +
                    "e8d3e0fb2e0d3628cf35e20c38d18906",
            derivation.deriveSecretToByteArray(ByteArray(0)).toHexString(),
        )
    }

    @Test
    fun saltIsCopiedAtDerivationConstruction() = testWithAlgorithm {
        val salt = "stable-salt".encodeToByteArray()
        val derivation = algorithm.secretDerivation(
            cost = 16,
            blockSize = 1,
            parallelization = 1,
            outputSize = 32.bytes,
            salt = salt,
            maximumMemoryBytes = 2816,
        )
        val expected = derivation.deriveSecretToByteArray("password".encodeToByteArray())

        salt.fill(0)

        assertContentEquals(expected, derivation.deriveSecretToByteArray("password".encodeToByteArray()))
    }

    @Test
    fun rejectsInvalidParametersBeforeDerivation() = testWithAlgorithm {
        fun assertInvalid(
            cost: Int = 16,
            blockSize: Int = 1,
            parallelization: Int = 1,
            outputSizeBytes: Int = 1,
            maximumMemoryBytes: Long = Long.MAX_VALUE,
        ) {
            assertFailsWith<IllegalArgumentException> {
                algorithm.secretDerivation(
                    cost = cost,
                    blockSize = blockSize,
                    parallelization = parallelization,
                    outputSize = outputSizeBytes.bytes,
                    salt = ByteArray(0),
                    maximumMemoryBytes = maximumMemoryBytes,
                )
            }
        }

        assertInvalid(cost = 1)
        assertInvalid(cost = 3)
        assertInvalid(blockSize = 0)
        assertInvalid(parallelization = 0)
        assertInvalid(outputSizeBytes = 0)
        assertInvalid(maximumMemoryBytes = 0)
        assertInvalid(cost = 65536, blockSize = 1)
        assertInvalid(blockSize = 2_097_152)
        assertInvalid(parallelization = 2_097_152)
        assertInvalid(maximumMemoryBytes = 2815)
    }
}
