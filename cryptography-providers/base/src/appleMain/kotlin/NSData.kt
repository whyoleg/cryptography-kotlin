/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base

import dev.whyoleg.cryptography.*
import kotlinx.cinterop.*
import platform.Foundation.*

private val EmptyNSData = NSData()

@CryptographyProviderApi
@OptIn(UnsafeNumber::class, ExperimentalForeignApi::class)
public fun NSData.toByteArray(): ByteArray {
    if (length.convert<Int>() == 0) return EmptyByteArray

    return ByteArray(length.convert()).apply {
        usePinned {
            getBytes(it.addressOf(0), length)
        }
    }
}

@CryptographyProviderApi
@OptIn(UnsafeNumber::class, ExperimentalForeignApi::class)
public fun <R> ByteArray.useNSData(block: (NSData) -> R): R {
    if (isEmpty()) return block(EmptyNSData)

    return usePinned {
        block(
            NSData.dataWithBytesNoCopy(
                bytes = it.addressOf(0),
                length = size.convert(),
                freeWhenDone = false
            )
        )
    }
}
