package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.posix.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = URandomCryptographyRandom

private object URandomCryptographyRandom : PlatformRandom() {
    override fun fillBytes(array: ByteArray) {
        val file = checkNotNull(fopen("/dev/urandom", "rb")) { "Failed to open /dev/urandom" }
        val result = array.usePinned { pinned ->
            fread(
                __ptr = pinned.addressOf(0),
                __size = 1.convert(),
                __n = pinned.get().size.convert(),
                __stream = file
            )
        }
        fclose(file)
        if (result <= 0UL) error("Failed to read from /dev/urandom")
    }
}
