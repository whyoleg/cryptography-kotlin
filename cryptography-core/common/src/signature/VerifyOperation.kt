package dev.whyoleg.cryptography.signature

import dev.whyoleg.vio.*

//TODO: rename parameters of inputs????
public interface VerifyOperation {
    public fun createFunction(): VerifyFunction
    public operator fun invoke(input: BufferView): Boolean
    public operator fun <R> invoke(block: VerifyFunction.() -> R): R //TODO: ext
}

public interface VerifyFunction : Closeable {
    public fun update(input: BufferView)
    public fun complete(input: BufferView): Boolean
}
