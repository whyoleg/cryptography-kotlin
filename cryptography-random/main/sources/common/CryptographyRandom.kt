package dev.whyoleg.cryptography.random

import kotlin.random.*

public abstract class CryptographyRandom : Random() {
    public companion object Default : CryptographyRandom() {
        private val defaultRandom: CryptographyRandom = defaultCryptographyRandom()

        override fun nextBits(bitCount: Int): Int = defaultRandom.nextBits(bitCount)
        override fun nextInt(): Int = defaultRandom.nextInt()
        override fun nextInt(until: Int): Int = defaultRandom.nextInt(until)
        override fun nextInt(from: Int, until: Int): Int = defaultRandom.nextInt(from, until)

        override fun nextLong(): Long = defaultRandom.nextLong()
        override fun nextLong(until: Long): Long = defaultRandom.nextLong(until)
        override fun nextLong(from: Long, until: Long): Long = defaultRandom.nextLong(from, until)

        override fun nextBoolean(): Boolean = defaultRandom.nextBoolean()

        override fun nextDouble(): Double = defaultRandom.nextDouble()
        override fun nextDouble(until: Double): Double = defaultRandom.nextDouble(until)
        override fun nextDouble(from: Double, until: Double): Double = defaultRandom.nextDouble(from, until)

        override fun nextFloat(): Float = defaultRandom.nextFloat()

        override fun nextBytes(array: ByteArray): ByteArray = defaultRandom.nextBytes(array)
        override fun nextBytes(size: Int): ByteArray = defaultRandom.nextBytes(size)
        override fun nextBytes(array: ByteArray, fromIndex: Int, toIndex: Int): ByteArray =
            defaultRandom.nextBytes(array, fromIndex, toIndex)
    }
}

internal expect fun defaultCryptographyRandom(): CryptographyRandom

internal abstract class PlatformRandom : CryptographyRandom() {
    final override fun nextBits(bitCount: Int): Int {
        val numBytes = (bitCount + 7) / 8
        val b = nextBytes(numBytes)

        var next = 0
        for (i in 0 until numBytes) {
            next = (next shl 8) + (b[i].toInt() and 0xFF)
        }
        return next ushr numBytes * 8 - bitCount
    }

    //we can also implement nextBytes(array, index, index)
    final override fun nextBytes(array: ByteArray): ByteArray {
        if (array.isNotEmpty()) fillBytes(array)
        return array
    }

    protected abstract fun fillBytes(array: ByteArray)
}
