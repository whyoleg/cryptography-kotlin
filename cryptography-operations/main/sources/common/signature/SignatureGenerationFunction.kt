package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*

public interface SignatureGenerationFunction : Closeable {
    public val signatureSize: Int

    public fun update(dataInput: Buffer)

    public fun finish(): Buffer
    public fun finish(signatureOutput: Buffer): Buffer
}
