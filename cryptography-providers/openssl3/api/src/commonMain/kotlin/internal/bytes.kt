/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import kotlinx.cinterop.*

private val almostEmptyArray = ByteArray(1).pin()

internal fun Pinned<ByteArray>.safeAddressOf(index: Int): CPointer<ByteVar> {
    if (index == get().size) return almostEmptyArray.addressOf(0)
    return addressOf(index)
}

//this hack should be dropped (or not?) with introducing of new IO or functions APIs
internal fun ByteArray.safeRefTo(index: Int): CValuesRef<ByteVar> {
    if (index == size) return almostEmptyArray.addressOf(0)
    return refTo(index)
}

//unsafe casts instead of asUByteArray().refTo() because of boxing when pinning
@Suppress("UNCHECKED_CAST")
internal fun ByteArray.safeRefToU(index: Int): CValuesRef<UByteVar> = safeRefTo(index) as CValuesRef<UByteVar>

@Suppress("UNCHECKED_CAST")
internal fun ByteArray.refToU(index: Int): CValuesRef<UByteVar> = refTo(index) as CValuesRef<UByteVar>

internal fun ByteArray.ensureSizeExactly(expectedSize: Int): ByteArray = when (size) {
    expectedSize -> this
    else         -> copyOf(expectedSize)
}

internal fun checkBounds(size: Int, startIndex: Int, endIndex: Int) {
    if (startIndex < 0 || endIndex > size) {
        throw IndexOutOfBoundsException(
            "startIndex ($startIndex) and endIndex ($endIndex) are not within the range [0..size($size))"
        )
    }
    if (startIndex > endIndex) {
        throw IllegalArgumentException("startIndex ($startIndex) > endIndex ($endIndex)")
    }
}
