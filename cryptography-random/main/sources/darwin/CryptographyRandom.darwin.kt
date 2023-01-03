package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = CCCryptographyRandom

private object CCCryptographyRandom : PlatformRandom() {
    override fun nextBytes(array: ByteArray): ByteArray {
        val size = array.size
        array.usePinned { pinned ->
            val status = CCRandomGenerateBytes(
                bytes = pinned.addressOf(0),
                count = size.convert()
            )
            if (status != kCCSuccess) error("CCRandomGenerateBytes failed: $status")
        }
        return array
    }
}
