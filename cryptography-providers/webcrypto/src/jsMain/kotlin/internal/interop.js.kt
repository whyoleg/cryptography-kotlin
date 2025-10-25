/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.coroutines.*
import kotlin.js.Promise

internal actual suspend fun <T : JsAny> Promise<T>.await(): T = suspendCoroutine { continuation ->
    then(
        { continuation.resume(it); null },
        { continuation.resumeWithException(it); null }
    )
}

internal actual fun ArrayBuffer.toByteArray(): ByteArray = Int8Array(this).unsafeCast<ByteArray>()

internal actual fun ByteArray.toInt8Array(): Int8Array = this.unsafeCast<Int8Array>()

internal actual fun Int8Array.toByteArray(): ByteArray = this.unsafeCast<ByteArray>()
