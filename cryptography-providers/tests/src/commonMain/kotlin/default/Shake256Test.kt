/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

abstract class Shake256Test(provider: CryptographyProvider) : AlgorithmTest<XOF>(SHAKE256, provider) {
    @Test
    fun rejectsZeroOutput() = testWithAlgorithm {
        assertFailsWith<IllegalArgumentException> { algorithm.hasher(0.bytes) }
    }

    @Test
    fun hashFunctionCanBeResetAndReused() = testWithAlgorithm {
        val input = "abc".encodeToByteArray()
        val hasher = algorithm.hasher(64.bytes)
        val expected = hasher.hash(input)

        hasher.createHashFunction().use { function ->
            repeat(2) {
                function.update(input)
                assertContentEquals(expected, function.hashToByteArray())
            }

            function.update("discard".encodeToByteArray())
            function.reset()
            function.update(input)
            assertContentEquals(expected, function.hashToByteArray())
        }
    }
}
