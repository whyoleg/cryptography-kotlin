/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.js.*

internal external class ArrayBuffer : JsAny

internal external class Int8Array : JsAny {
    constructor(length: Int)
    constructor(buffer: ArrayBuffer)

    val length: Int
    val buffer: ArrayBuffer
    val byteOffset: Int
    val byteLength: Int
    fun subarray(start: Int, end: Int): Int8Array
}

internal external class Uint8Array : JsAny {
    constructor(buffer: ArrayBuffer, byteOffset: Int, length: Int)
}

internal expect fun ByteArray.toInt8Array(): Int8Array

internal expect fun ArrayBuffer.toByteArray(): ByteArray

internal expect fun Int8Array.toByteArray(): ByteArray

internal expect suspend fun <T : JsAny> Promise<T>.await(): T

internal fun Array<String>.toJsArray(): JsArray<JsString> = JsArray<JsString>().also {
    forEachIndexed { index, value ->
        it[index] = value.toJsString()
    }
}
