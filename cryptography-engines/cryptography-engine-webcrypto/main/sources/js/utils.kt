package dev.whyoleg.cryptography.webcrypto

import kotlin.coroutines.*
import kotlin.js.*

internal suspend fun <T> Promise<T>.await() = suspendCoroutine<T> { continuation ->
    then(
        { continuation.resume(it) },
        { continuation.resumeWithException(it) }
    )
}
