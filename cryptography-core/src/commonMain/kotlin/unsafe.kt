/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

@Suppress("NOTHING_TO_INLINE")
@OptIn(UnsafeByteStringApi::class)
internal inline fun ByteArray.asByteString(): ByteString {
    return UnsafeByteStringOperations.wrapUnsafe(this)
}

@Suppress("NOTHING_TO_INLINE")
@OptIn(UnsafeByteStringApi::class)
internal inline fun ByteString.asByteArray(): ByteArray {
    UnsafeByteStringOperations.withByteArrayUnsafe(this) { return it }
}
