/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.coroutines.*
import kotlin.js.Promise

internal suspend fun <T : JsAny> Promise<T>.await() = suspendCoroutine { continuation ->
    then(
        { continuation.resume(it); null },
        { continuation.resumeWithException(Throwable(it.toString())); null }
    )
}

internal fun ByteArray.toInt8Array(): Int8Array {
    val array = Int8Array(size)
    repeat(size) { array[it] = this[it] }
    return array
}

internal fun ArrayBuffer.toByteArray(): ByteArray {
    return Int8Array(this).toByteArray()
}

internal fun Int8Array.toByteArray(): ByteArray {
    return ByteArray(length) { this[it] }
}

internal external class Uint8Array : JsAny {
    constructor(buffer: ArrayBuffer, byteOffset: Int, length: Int)
}

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

private fun getImpl(obj: Int8Array, index: Int): Byte = js("obj[index]")
private fun setImpl(obj: Int8Array, index: Int, value: Byte): Unit = js("obj[index] = value")

private operator fun Int8Array.get(index: Int): Byte = getImpl(this, index)
private operator fun Int8Array.set(index: Int, value: Byte) = setImpl(this, index, value)
