package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.io.*

public interface KeyDecoder<KF : KeyFormat, K : Key> {
    public suspend fun decodeFrom(format: KF, input: Buffer): K
    public fun decodeFromBlocking(format: KF, input: Buffer): K
}
