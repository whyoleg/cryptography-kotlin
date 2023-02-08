package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

private val almostEmptyArray = ByteArray(1)

//this hack will be dropped with introducing of new IO or functions APIs
internal fun ByteArray.fixEmpty(): ByteArray = if (isNotEmpty()) this else almostEmptyArray

internal fun checkError(result: size_t): size_t {
    if (result > 0u) return result
    println(result)
    fail()
}

internal fun checkError(result: Int): Int {
    if (result > 0) return result
    println(result)
    fail()
}

@OptIn(UnsafeNumber::class)
private fun fail(): Nothing {
    val code = ERR_get_error()
    println(code)
    val message = memScoped {
        val buffer = allocArray<ByteVar>(256)
        ERR_error_string(code, buffer)?.toKString()
    }
    throw CryptographyException("OPENSSL error: $message")
}
