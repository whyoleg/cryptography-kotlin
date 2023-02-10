package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal fun <T : Any> checkError(result: T?): T {
    if (result != null) return result
    fail(0)
}

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
