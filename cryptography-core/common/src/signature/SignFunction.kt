package dev.whyoleg.cryptography.signature

import dev.whyoleg.vio.*

public inline fun <R> Signer.Stream.sign(block: SignFunction.() -> R): R {
    return createSignFunction().use(block)
}


public interface SignFunction : Closeable {
    public val signatureSize: BinarySize

    public fun signPart(input: BufferView)

    public fun signFinalPart(input: BufferView): BufferView
    public fun signFinalPart(input: BufferView, output: BufferView): BufferView
}
