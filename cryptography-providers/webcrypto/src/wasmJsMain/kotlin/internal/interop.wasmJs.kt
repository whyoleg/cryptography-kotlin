/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*
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
