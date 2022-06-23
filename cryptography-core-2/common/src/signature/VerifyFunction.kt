package dev.whyoleg.cryptography.signature

import dev.whyoleg.vio.*


public inline fun <R> Verifier.Stream.verify(block: VerifyFunction.() -> R): R {
    return createVerifyFunction().use(block)
}

public interface VerifyFunction : Closeable {
    public val signatureSize: BinarySize

    public fun verifyPart(input: BufferView)

    public fun verifyFinalPart(input: BufferView): Boolean
}
