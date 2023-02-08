package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

private val almostEmptyArray = ByteArray(1)

//this hack should be dropped (or not?) with introducing of new IO or functions APIs
internal fun ByteArray.safeRefTo(index: Int): CValuesRef<ByteVar> {
    if (index == size) return almostEmptyArray.refTo(0)
    return refTo(index)
}

@OptIn(ExperimentalUnsignedTypes::class)
internal fun ByteArray.safeRefToU(index: Int): CValuesRef<UByteVar> {
    if (index == size) return almostEmptyArray.asUByteArray().refTo(0)
    return asUByteArray().refTo(index)
}

@OptIn(ExperimentalUnsignedTypes::class)
internal fun ByteArray.refToU(index: Int): CValuesRef<UByteVar> = asUByteArray().refTo(index)

internal fun checkError(result: size_t): size_t {
    if (result > 0u) return result
    fail(result.convert())
}

internal fun checkError(result: Int): Int {
    if (result > 0) return result
    fail(result)
}

@OptIn(UnsafeNumber::class)
private fun fail(result: Int): Nothing {
    val code = ERR_get_error()
    val message = memScoped {
        val buffer = allocArray<ByteVar>(256)
        ERR_error_string(code, buffer)?.toKString()
    }
    throw CryptographyException("OPENSSL failure: $message (result: $result, code: $code)")
}
