/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.windows.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = BCryptCryptographyRandom

private object BCryptCryptographyRandom : PlatformRandom() {
    override fun fillBytes(array: ByteArray) {
        @OptIn(ExperimentalUnsignedTypes::class)
        val status = array.asUByteArray().usePinned { pinned ->
            BCryptGenRandom(
                hAlgorithm = null,
                pbBuffer = pinned.addressOf(0),
                cbBuffer = pinned.get().size.convert(),
                dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG.toUInt()
            )
        }
        if (status != 0) error("BCryptGenRandom failed: $status")
    }
}
