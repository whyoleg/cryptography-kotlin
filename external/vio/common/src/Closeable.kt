package dev.whyoleg.vio

public expect fun interface Closeable {
    public fun close()
}

//TODO
public inline fun <C : Closeable, R> C.use(block: (C) -> R): R {
    try {
        return block(this)
    } finally {
        close()
    }
}
