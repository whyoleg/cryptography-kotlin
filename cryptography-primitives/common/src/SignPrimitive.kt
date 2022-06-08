package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface SignPrimitive {
    public val signatureSize: SignatureSize

    public fun sign(input: BufferView): BufferView
    public fun sign(input: BufferView, output: BufferView): BufferView

    public fun signFunction(): SignFunction
}

public inline fun <R> SignPrimitive.sign(block: SignFunction.() -> R): R {
    return signFunction().use(block)
}

public interface SignFunction : Closeable {
    public val signatureSize: SignatureSize

    public fun signPart(input: BufferView)

    public fun signFinalPart(input: BufferView): BufferView
    public fun signFinalPart(input: BufferView, output: BufferView): BufferView
}
