/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.coroutines.*
import kotlin.js.Promise

internal actual suspend fun <T : JsAny> Promise<T>.await(): T = suspendCoroutine { continuation ->
    then(
        { continuation.resume(it); null },
        { continuation.resumeWithException(Throwable(it.toString())); null }
    )
}

internal actual fun ByteArray.toInt8Array(): Int8Array {
    val array = Int8Array(size)
    repeat(size) { setByte(array, it, this[it]) }
    return array
}

internal actual fun ArrayBuffer.toByteArray(): ByteArray {
    return Int8Array(this).toByteArray()
}

internal actual fun Int8Array.toByteArray(): ByteArray {
    return ByteArray(length) { getByte(this, it) }
}

private fun getByte(obj: Int8Array, index: Int): Byte = js("obj[index]")
private fun setByte(obj: Int8Array, index: Int, value: Byte): Unit = js("obj[index] = value")
