/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.test

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

private val almostEmptyArray = ByteArray(1)

//this hack will be dropped with introducing of new IO or functions APIs
internal fun ByteArray.fixEmpty(): ByteArray = if (isNotEmpty()) this else almostEmptyArray

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
    error("OPENSSL error: $message")
}

private const val hexCode = "0123456789ABCDEF"

internal fun parseHexBinary(s: String): ByteArray {
    val len = s.length
    require(len % 2 == 0) { "HexBinary string must be even length" }
    val bytes = ByteArray(len / 2)
    var i = 0

    while (i < len) {
        val h = hexToInt(s[i])
        val l = hexToInt(s[i + 1])
        require(!(h == -1 || l == -1)) { "Invalid hex chars: ${s[i]}${s[i + 1]}" }

        bytes[i / 2] = ((h shl 4) + l).toByte()
        i += 2
    }

    return bytes
}

private fun hexToInt(ch: Char): Int = when (ch) {
    in '0'..'9' -> ch - '0'
    in 'A'..'F' -> ch - 'A' + 10
    in 'a'..'f' -> ch - 'a' + 10
    else        -> -1
}

internal fun printHexBinary(data: ByteArray, lowerCase: Boolean = true): String {
    val r = StringBuilder(data.size * 2)
    for (b in data) {
        r.append(hexCode[b.toInt() shr 4 and 0xF])
        r.append(hexCode[b.toInt() and 0xF])
    }
    return if (lowerCase) r.toString().lowercase() else r.toString()
}

internal fun NativePlacement.OSSL_PARAM_array(vararg values: CValue<OSSL_PARAM>): CArrayPointer<OSSL_PARAM> {
    val params = allocArray<OSSL_PARAM>(values.size + 1)
    values.forEachIndexed { index, value -> value.place(params[index].ptr) }
    OSSL_PARAM_construct_end().place(params[values.size].ptr)
    return params
}
