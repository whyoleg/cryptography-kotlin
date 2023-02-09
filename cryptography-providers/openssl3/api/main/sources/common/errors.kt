package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal inline fun <T : Any> checkError(result: T?, onFailure: () -> Unit = {}): T {
    if (result != null) return result
    onFailure()
    fail(0)
}

internal inline fun checkError(result: size_t, onFailure: () -> Unit = {}): size_t {
    if (result > 0u) return result
    onFailure()
    fail(result.convert())
}

internal inline fun checkError(result: Int, onFailure: () -> Unit = {}): Int {
    if (result > 0) return result
    onFailure()
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
