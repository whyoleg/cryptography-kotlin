package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface HashFunction : CryptographyFunction {
    public val digestSize: BinarySize

    public fun hashPart(input: BufferView)

    public fun hashFinalPart(input: BufferView): Digest
    public fun hashFinalPart(input: BufferView, output: Digest): Digest
}
