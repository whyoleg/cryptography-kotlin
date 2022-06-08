package dev.whyoleg.cryptography.signature

import dev.whyoleg.vio.*

public interface Signer {
    public val signatureSize: SignatureSize

    public fun sign(input: BufferView): BufferView
    public fun sign(input: BufferView, output: BufferView): BufferView

    public fun signFunction(): SignFunction
}

public inline fun <R> Signer.sign(block: SignFunction.() -> R): R {
    return signFunction().use(block)
}

public interface SignFunction : Closeable {
    public val signatureSize: SignatureSize

    public fun signPart(input: BufferView)

    public fun signFinalPart(input: BufferView): BufferView
    public fun signFinalPart(input: BufferView, output: BufferView): BufferView
}
