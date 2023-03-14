/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlin.test.*

class DefaultRandomTest : CryptographyRandomTest(CryptographyRandom.Default)

abstract class CryptographyRandomTest(private val random: CryptographyRandom) {
    @Test
    fun testInt() {
        assertNotEquals(random.nextInt(), random.nextInt())
    }

    @Test
    fun testEmpty() {
        assertTrue(random.nextBytes(0).isEmpty())
        assertTrue(random.nextBytes(ByteArray(0)).isEmpty())
    }

    @Test
    fun testInPlace() {
        val bytes = ByteArray(10) { it.toByte() }
        bytes.copyOf().also { copy ->
            assertContentEquals(bytes, copy)
            val inPlace = random.nextBytes(copy)
            assertContentEquals(inPlace, copy)
            assertFalse(bytes.contentEquals(inPlace))
            assertFalse(bytes.contentEquals(copy))
        }
        bytes.copyOf().also { copy ->
            val inPlace = random.nextBytes(copy, 5, 5)
            assertContentEquals(inPlace, copy)
            assertContentEquals(bytes, inPlace)
            assertContentEquals(bytes, copy)
        }
        bytes.copyOf().also { copy ->
            val inPlace = random.nextBytes(copy, 0, 5)
            assertContentEquals(inPlace, copy)
            assertFalse(bytes.contentEquals(inPlace))
            assertFalse(bytes.contentEquals(copy))
        }
    }

    @Test
    fun testComposite() {
        fun targetValues(value: Int): List<Int> = buildList {
            fun addLocal(value: Int) {
                add(value)
                add(value + 1)
                add(value - 1)
            }

            addLocal(value)
            (2..8).forEach { split ->
                val div = value / split
                val multi = value * split
                addLocal(value)
                addLocal(div)
                addLocal(multi)
                addLocal(multi - div)
            }
        }

        val sizes = listOf(
            32, //min jdk native prng chunk
            256, //linux chunk
            512,
            4096,
            65536, //webcrypto chunk | max jdk native prng chunk
            1000000, // 1 MB
            1048576, // 1 MiB (via targetValues will test values up to 8 MiB)
        ).flatMap(::targetValues).distinct().sorted()

        sizes.forEach { size ->
            val bytes = random.nextBytes(size)
            val refillBytes = random.nextBytes(bytes.copyOf())
            assertEquals(bytes.size, size)
            assertEquals(refillBytes.size, size)

            var nonEmptyCount = 0
            var changedCount = 0

            repeat(size) {
                val original = bytes[it]
                val changed = refillBytes[it]
                if (original != 0.toByte()) ++nonEmptyCount
                if (original != changed) ++changedCount
            }

            val nonEmptyProb = 1.0 - nonEmptyCount.toDouble() / size
            val changedProb = 1.0 - changedCount.toDouble() / size

            // empirical values
            val tolerance = when {
                size < 4      -> 0.7
                size < 6      -> 0.5
                size < 20     -> 0.3
                size < 50     -> 0.2
                size < 100    -> 0.1
                size < 200    -> 0.05
                size < 500    -> 0.035
                size < 1000   -> 0.025
                size < 5000   -> 0.02
                size < 10000  -> 0.01
                size < 100000 -> 0.0075
                else          -> 0.005
            }

            assertEquals(0.0, nonEmptyProb, tolerance, "size=$size EMPTY diff = $nonEmptyProb")
            assertEquals(0.0, changedProb, tolerance, "size=$size CHANGED diff = $changedProb")
        }
    }

}
