package dev.whyoleg.cryptography.io

public expect interface Closeable {
    public fun close()
}

public inline fun <C : Closeable, R> C.use(block: (C) -> R): R {
    try {
        return block(this)
    } finally {
        close()
    }
}
