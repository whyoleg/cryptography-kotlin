/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*
import kotlin.coroutines.*
import kotlin.js.Promise

internal suspend fun <T> Promise<T>.await() = suspendCoroutine { continuation ->
    then(
        { continuation.resume(it); null },
        { continuation.resumeWithException(it); null }
    )
}

internal fun ArrayBuffer.toByteArray(): ByteArray = Int8Array(this).unsafeCast<ByteArray>()

internal fun ByteArray.toInt8Array(): Int8Array = this.unsafeCast<Int8Array>()
