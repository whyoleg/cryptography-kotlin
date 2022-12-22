package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.io.*

public interface HashFunction : Closeable {
    public val digestSize: Int
    public fun update(dataInput: Buffer)

    //TODO: name - finalize?
    public fun finish(): Buffer
    public fun finish(digestOutput: Buffer): Buffer
}
