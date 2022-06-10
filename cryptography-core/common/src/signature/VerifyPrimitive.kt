package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface VerifyPrimitive : CryptographyPrimitive {
    public val signatureSize: BinarySize

    public fun verify(input: Signature): Boolean

    public suspend fun verifySuspend(input: Signature): Boolean

    public fun verifyFunction(): VerifyFunction
}

public inline fun <R> VerifyPrimitive.verify(block: VerifyFunction.() -> R): R {
    return verifyFunction().use(block)
}

