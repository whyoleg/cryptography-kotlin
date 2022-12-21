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
public interface BlockingAdaptor {
    public fun <T> execute(block: suspend () -> T): T
}

public interface SuspendAdaptor {
    public suspend fun <T> execute(block: () -> T): T
}
