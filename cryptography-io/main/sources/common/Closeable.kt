package dev.whyoleg.cryptography.io

import kotlin.contracts.*

public expect interface Closeable {
    public fun close()
}

@OptIn(ExperimentalContracts::class)
public inline fun <C : Closeable?, R> C.use(block: (C) -> R): R {
    contract {
        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
    }
    var exception: Throwable? = null
    try {
        return block(this)
    } catch (e: Throwable) {
        exception = e
        throw e
    } finally {
        closeFinally(exception)
    }
}

@PublishedApi
internal fun Closeable?.closeFinally(cause: Throwable?): Unit = when {
    this == null  -> {}
    cause == null -> close()
    else          -> try {
        close()
    } catch (closeException: Throwable) {
        cause.addSuppressed(closeException)
    }
}
