/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = CCCryptographyRandom

private object CCCryptographyRandom : AbstractRandom() {

    override fun fillBytes(array: ByteArray) {
        val size = array.size

        @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
        val status = array.usePinned { pinned ->
            CCRandomGenerateBytes(pinned.addressOf(0), size.convert())
        }
        checkStatus(status)
    }
}

private fun checkStatus(status: CCRNGStatus) {
    val message = when (status) {
        kCCSuccess           -> return
        kCCRNGFailure        -> "Random number generator failure"
        kCCMemoryFailure     -> "Memory allocation failure"
        kCCUnimplemented     -> "Function not implemented for the current algorithm"
        kCCAlignmentError    -> "Input size was not aligned properly"
        kCCUnspecifiedError  -> "An internal error has been detected, but the exact cause is unknown"
        kCCBufferTooSmall    -> "Insufficent buffer provided for specified operation"
        kCCOverflow          -> "Operation will result in overflow"
        kCCParamError        -> "Illegal parameter value"
        kCCDecodeError       -> "Input data did not decode or decrypt properly"
        kCCCallSequenceError -> "Function was called in an improper sequence"
        else                 -> "Unknown error"
    }
    error("CCRandomGenerateBytes failed[status=$status]: $message")
}
