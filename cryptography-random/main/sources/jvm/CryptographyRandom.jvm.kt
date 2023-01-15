package dev.whyoleg.cryptography.random

import java.security.*

public fun SecureRandom.asCryptographyRandom(): CryptographyRandom = CryptographyRandomImpl(this)

public fun CryptographyRandom.asSecureRandom(): SecureRandom = when (this) {
    is CryptographyRandomImpl -> secureRandom
    else                      -> SecureRandomImpl(this)
}

internal actual fun defaultCryptographyRandom(): CryptographyRandom = SecureRandom().asCryptographyRandom()

private class CryptographyRandomImpl(
    val secureRandom: SecureRandom,
) : CryptographyRandom() {
    override fun nextBits(bitCount: Int): Int = secureRandom.nextInt().takeUpperBits(bitCount)
    override fun nextInt(): Int = secureRandom.nextInt()
    override fun nextInt(until: Int): Int = secureRandom.nextInt(until)
    override fun nextLong(): Long = secureRandom.nextLong()
    override fun nextBoolean(): Boolean = secureRandom.nextBoolean()
    override fun nextDouble(): Double = secureRandom.nextDouble()
    override fun nextFloat(): Float = secureRandom.nextFloat()
    override fun nextBytes(array: ByteArray): ByteArray {
        if (array.isEmpty()) return array

        return array.also { secureRandom.nextBytes(it) }
    }
}

private fun Int.takeUpperBits(bitCount: Int): Int =
    ushr(32 - bitCount) and (-bitCount).shr(31)

private class SecureRandomImpl(
    cryptographyRandom: CryptographyRandom,
) : SecureRandom(SecureRandomSpiImpl(cryptographyRandom), null)

private class SecureRandomSpiImpl(
    private val cryptographyRandom: CryptographyRandom,
) : SecureRandomSpi() {
    override fun engineSetSeed(seed: ByteArray) {
        throw UnsupportedOperationException()
    }

    override fun engineNextBytes(bytes: ByteArray) {
        if (bytes.isEmpty()) return

        cryptographyRandom.nextBytes(bytes)
    }

    override fun engineGenerateSeed(numBytes: Int): ByteArray {
        throw UnsupportedOperationException()
    }
}
