/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import kotlin.test.*

@OptIn(CryptographyProviderApi::class)
class BaseScryptTest {
    @Test
    fun acceptsRepresentativeParameterCombinations() {
        assertValid(cost = 2, blockSize = 1, parallelization = 1, maximumMemoryBytes = 1024)
        assertValid(cost = 16, blockSize = 1, parallelization = 1, maximumMemoryBytes = 2816)
        assertValid(cost = 1024, blockSize = 8, parallelization = 16, maximumMemoryBytes = 1_085_440)
        assertValid(cost = 16384, blockSize = 8, parallelization = 1, maximumMemoryBytes = 16_783_360)
        assertValid(cost = 1 shl 17, blockSize = 8, parallelization = 1, maximumMemoryBytes = 134_223_872)
        assertValid(cost = 1 shl 30, blockSize = 2, parallelization = 1, maximumMemoryBytes = 274_877_908_480)
    }

    @Test
    fun acceptsOwaspRecommendedParameters() {
        assertValid(cost = 1 shl 17, blockSize = 8, parallelization = 1, maximumMemoryBytes = 134_223_872)
        assertValid(cost = 1 shl 16, blockSize = 8, parallelization = 2, maximumMemoryBytes = 67_117_056)
        assertValid(cost = 1 shl 15, blockSize = 8, parallelization = 3, maximumMemoryBytes = 33_564_672)
        assertValid(cost = 1 shl 14, blockSize = 8, parallelization = 5, maximumMemoryBytes = 16_791_552)
        assertValid(cost = 1 shl 13, blockSize = 8, parallelization = 10, maximumMemoryBytes = 8_413_184)
    }

    @Test
    fun validatesCost() {
        assertInvalid("cost must be greater than 1 and a power of two", cost = Int.MIN_VALUE)
        assertInvalid("cost must be greater than 1 and a power of two", cost = 0)
        assertInvalid("cost must be greater than 1 and a power of two", cost = 1)
        assertInvalid("cost must be greater than 1 and a power of two", cost = 3)
        assertInvalid("cost must be less than 65536 when blockSize is 1", cost = 65536)
    }

    @Test
    fun validatesBlockSizeAndParallelization() {
        assertInvalid("blockSize must be at least 1", blockSize = -1)
        assertInvalid("blockSize must be at least 1", blockSize = 0)
        assertInvalid("parallelization must be at least 1", parallelization = -1)
        assertInvalid("parallelization must be at least 1", parallelization = 0)

        assertValid(
            cost = 16,
            blockSize = 1,
            parallelization = 2_097_151,
            maximumMemoryBytes = 536_873_216,
        )
        assertInvalid(
            "parallelization is too large for blockSize",
            parallelization = 2_097_152,
        )

        assertValid(
            cost = 16,
            blockSize = 2_097_151,
            parallelization = 1,
            maximumMemoryBytes = 5_905_577_216,
        )
        assertInvalid(
            "parallelization is too large for blockSize",
            blockSize = 2_097_152,
        )
    }

    @Test
    fun validatesOutputSizeAndMemoryBudget() {
        assertInvalid("outputSize must be at least 1 byte", outputSizeBytes = 0)
        assertInvalid("maximumMemoryBytes must be greater than 0", maximumMemoryBytes = -1)
        assertInvalid("maximumMemoryBytes must be greater than 0", maximumMemoryBytes = 0)

        assertValid(cost = 16, blockSize = 1, parallelization = 1, maximumMemoryBytes = 2816)
        assertInvalid(
            "maximumMemoryBytes must be at least 2816 for these scrypt parameters",
            maximumMemoryBytes = 2815,
        )

        assertValid(cost = 1 shl 17, blockSize = 8, parallelization = 1, maximumMemoryBytes = 134_223_872)
        assertInvalid(
            "maximumMemoryBytes must be at least 134223872 for these scrypt parameters",
            cost = 1 shl 17,
            blockSize = 8,
            maximumMemoryBytes = 134_223_871,
        )
    }

    private fun assertValid(
        cost: Int = 16,
        blockSize: Int = 1,
        parallelization: Int = 1,
        maximumMemoryBytes: Long = Long.MAX_VALUE,
        outputSizeBytes: Int = 1,
    ) {
        validateScryptParameters(
            cost = cost,
            blockSize = blockSize,
            parallelization = parallelization,
            maximumMemoryBytes = maximumMemoryBytes,
            outputSize = outputSizeBytes.bytes,
        )
    }

    private fun assertInvalid(
        expectedMessage: String,
        cost: Int = 16,
        blockSize: Int = 1,
        parallelization: Int = 1,
        maximumMemoryBytes: Long = Long.MAX_VALUE,
        outputSizeBytes: Int = 1,
    ) {
        val exception = assertFailsWith<IllegalArgumentException> {
            assertValid(cost, blockSize, parallelization, maximumMemoryBytes, outputSizeBytes)
        }
        assertEquals(expectedMessage, exception.message)
    }
}
