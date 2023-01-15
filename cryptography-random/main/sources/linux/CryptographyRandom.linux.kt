package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.posix.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = URandomCryptographyRandom

private object URandomCryptographyRandom : PlatformRandom() {
    override fun nextBytes(array: ByteArray): ByteArray {
        if (array.isEmpty()) return array

        //TODO: handle null?
        val fd = fopen("/dev/urandom", "rb") ?: return array
        val size = array.size
        array.usePinned { pinned ->
            fread(pinned.addressOf(0), 1.convert(), size.convert(), fd)
        }
        fclose(fd)
        return array
    }
}
