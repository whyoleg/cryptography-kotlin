package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.*
import kotlin.coroutines.*
import kotlin.js.*

internal suspend fun <T> Promise<T>.await() = suspendCoroutine<T> { continuation ->
    then(
        { continuation.resume(it) },
        { continuation.resumeWithException(it) }
    )
}

internal fun nonBlocking(): Nothing = throw CryptographyException("Only non-blocking(suspend) calls are supported in WebCrypto")

internal fun noFunction(): Nothing = throw CryptographyException("Function operations are not supported in WebCrypto")
