package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface VerifyPrimitive {
    public val signatureSize: SignatureSize

    public fun verify(input: BufferView): Boolean

    public fun verifyFunction(): VerifyFunction
}

public inline fun <R> VerifyPrimitive.verify(block: VerifyFunction.() -> R): R {
    return verifyFunction().use(block)
}

public interface VerifyFunction : Closeable {
    public fun verifyPart(input: BufferView)
    public fun verifyFinalPart(input: BufferView): Boolean
}
