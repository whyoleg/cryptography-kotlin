package dev.whyoleg.cryptography

public typealias Buffer = ByteArray

//TODO expect/actual
public interface Closeable {
    public fun close()
}

public inline fun <C : Closeable, R> C.use(block: (C) -> R): R {
    try {
        return block(this)
    } finally {
        close()
    }
}

//TODO
public fun interface BlockingAdaptor<T> {
    public fun run(block: suspend () -> T): T
}

public fun interface SuspendAdaptor<T> {
    public suspend fun run(block: () -> T): T
}
