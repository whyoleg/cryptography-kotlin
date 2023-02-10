package dev.whyoleg.cryptography.openssl3

import kotlinx.cinterop.*

private val almostEmptyArray = ByteArray(1).pin()

//this hack should be dropped (or not?) with introducing of new IO or functions APIs
internal fun ByteArray.safeRefTo(index: Int): CValuesRef<ByteVar> {
    if (index == size) return almostEmptyArray.addressOf(0)
    return refTo(index)
}

//unsafe casts instead of asUByteArray().refTo() because of boxing when pinning
internal fun ByteArray.safeRefToU(index: Int): CValuesRef<UByteVar> {
    return safeRefTo(index) as CValuesRef<UByteVar>
}

internal fun ByteArray.refToU(index: Int): CValuesRef<UByteVar> = refTo(index) as CValuesRef<UByteVar>

internal fun ByteArray.ensureSizeExactly(expectedSize: Int): ByteArray = when (size) {
    expectedSize -> this
    else         -> copyOf(expectedSize)
}

internal inline fun <reified T : CVariable, R> NativeFreeablePlacement.safeAlloc(block: (value: T) -> R): R {
    val value = alloc<T>()
    try {
        return block(value)
    } catch (cause: Throwable) {
        free(value)
        throw cause
    }
}
