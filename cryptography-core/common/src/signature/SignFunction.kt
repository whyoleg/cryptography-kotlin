package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface SignFunction : CryptographyFunction {
    public val signatureSize: BinarySize

    public fun signPart(input: BufferView)

    public fun signFinalPart(input: BufferView): Signature
    public fun signFinalPart(input: BufferView, output: Signature): Signature
}
