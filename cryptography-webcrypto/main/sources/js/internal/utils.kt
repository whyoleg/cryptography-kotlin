package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.*
import org.khronos.webgl.*
import kotlin.coroutines.*
import kotlin.js.Promise

internal suspend fun <T> Promise<T>.await() = suspendCoroutine<T> { continuation ->
    then(
        { continuation.resume(it) },
        { continuation.resumeWithException(it) }
    )
}

internal fun nonBlocking(): Nothing = throw CryptographyException("Only non-blocking(suspend) calls are supported in WebCrypto")

internal fun ArrayBuffer.toByteArray(): ByteArray = Int8Array(this).unsafeCast<ByteArray>()
