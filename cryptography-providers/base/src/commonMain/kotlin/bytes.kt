/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base

import dev.whyoleg.cryptography.*

@CryptographyProviderApi
public val EmptyByteArray: ByteArray = ByteArray(0)

@CryptographyProviderApi
public fun checkBounds(size: Int, startIndex: Int, endIndex: Int) {
    if (startIndex < 0 || endIndex > size) {
        throw IndexOutOfBoundsException(
            "startIndex ($startIndex) and endIndex ($endIndex) are not within the range [0..size($size))"
        )
    }
    if (startIndex > endIndex) {
        throw IllegalArgumentException("startIndex ($startIndex) > endIndex ($endIndex)")
    }
}

@CryptographyProviderApi
public fun ByteArray.ensureSizeExactly(expectedSize: Int): ByteArray = when (size) {
    expectedSize -> this
    else         -> copyOf(expectedSize)
}
