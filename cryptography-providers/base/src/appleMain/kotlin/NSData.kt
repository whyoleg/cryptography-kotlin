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
public fun NSData.getIntoByteArray(
    destination: ByteArray,
    destinationOffset: Int = 0,
): Int {
    val outputSize = length.convert<Int>()
    if (outputSize == 0) return 0
    checkBounds(destination.size, destinationOffset, destinationOffset + outputSize)

    destination.usePinned {
        getBytes(it.addressOf(destinationOffset), length)
    }
    return outputSize
}

@CryptographyProviderApi
@OptIn(UnsafeNumber::class, ExperimentalForeignApi::class)
public fun NSData.toByteArray(): ByteArray {
    if (length.convert<Int>() == 0) return EmptyByteArray

    return ByteArray(length.convert()).also {
        getIntoByteArray(it)
    }
}

@CryptographyProviderApi
@OptIn(UnsafeNumber::class, ExperimentalForeignApi::class)
public fun <R> ByteArray.useNSData(
    startIndex: Int = 0,
    endIndex: Int = size,
    block: (NSData) -> R,
): R {
    if (isEmpty()) return block(EmptyNSData)
    checkBounds(size, startIndex, endIndex)

    return usePinned {
        block(
            NSData.dataWithBytesNoCopy(
                bytes = it.addressOf(startIndex),
                length = (endIndex - startIndex).convert(),
                freeWhenDone = false
            )
        )
    }
}
