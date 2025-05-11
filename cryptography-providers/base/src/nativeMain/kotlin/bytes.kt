/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base

import dev.whyoleg.cryptography.*
import kotlinx.cinterop.*

// this hack should be dropped (or not?) with introducing of new IO or functions APIs

@OptIn(ExperimentalForeignApi::class)
private val almostEmptyArrayPinned = ByteArray(1).pin()

@ExperimentalForeignApi
public fun Pinned<ByteArray>.safeAddressOf(index: Int): CPointer<ByteVar> {
    if (index == get().size) return almostEmptyArrayPinned.addressOf(0)
    return addressOf(index)
}

@CryptographyProviderApi
@ExperimentalForeignApi
public fun ByteArray.safeRefTo(index: Int): CValuesRef<ByteVar> {
    if (index == size) return almostEmptyArrayPinned.addressOf(0)
    return refTo(index)
}

//unsafe casts instead of asUByteArray().refTo() because of boxing when pinning
@CryptographyProviderApi
@ExperimentalForeignApi
@Suppress("UNCHECKED_CAST")
public fun Pinned<ByteArray>.safeAddressOfU(index: Int): CPointer<UByteVar> = safeAddressOf(index) as CPointer<UByteVar>

@CryptographyProviderApi
@ExperimentalForeignApi
@Suppress("UNCHECKED_CAST")
public fun ByteArray.safeRefToU(index: Int): CValuesRef<UByteVar> = safeRefTo(index) as CValuesRef<UByteVar>

@CryptographyProviderApi
@ExperimentalForeignApi
@Suppress("UNCHECKED_CAST")
public fun ByteArray.refToU(index: Int): CValuesRef<UByteVar> = refTo(index) as CValuesRef<UByteVar>
