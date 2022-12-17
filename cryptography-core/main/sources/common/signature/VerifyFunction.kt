package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*

public interface VerifyFunction : Closeable {
    public val signatureSize: Int

    public fun update(signatureInput: Buffer)

    public fun finish(): Boolean
}
