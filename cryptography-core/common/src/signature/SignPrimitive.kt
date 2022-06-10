package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface SignPrimitive: CryptographyPrimitive {
    public val signatureSize: BinarySize

    public fun sign(input: BufferView): Signature
    public fun sign(input: BufferView, output: BufferView): Signature

    public suspend fun signSuspend(input: BufferView): Signature
    public suspend fun signSuspend(input: BufferView, output: BufferView): Signature

    public fun signFunction(): SignFunction
}

public inline fun <R> SignPrimitive.sign(block: SignFunction.() -> R): R {
    return signFunction().use(block)
}
