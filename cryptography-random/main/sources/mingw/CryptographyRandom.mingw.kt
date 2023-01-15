package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.windows.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = BCryptCryptographyRandom

private object BCryptCryptographyRandom : PlatformRandom() {
    override fun nextBytes(array: ByteArray): ByteArray {
        if (array.isEmpty()) return array

        val size = array.size
        @OptIn(ExperimentalUnsignedTypes::class)
        array.asUByteArray().usePinned { pinned ->
            val status = BCryptGenRandom(
                hAlgorithm = null,
                pbBuffer = pinned.addressOf(0),
                cbBuffer = size.convert(),
                dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG
            )
            if (status != 0) error("BCryptGenRandom failed: $status")
        }
        return array
    }
}
