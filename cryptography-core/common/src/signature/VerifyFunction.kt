package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*

public interface VerifyFunction : CryptographyFunction {
    public fun verifyPart(input: Signature)
    public fun verifyFinalPart(input: Signature): Boolean
}
