package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.io.*

public interface EncodableKey<KF : KeyFormat> : Key {
    public suspend fun encodeTo(format: KF): Buffer
    public suspend fun encodeTo(format: KF, output: Buffer): Buffer
    public fun encodeToBlocking(format: KF): Buffer
    public fun encodeToBlocking(format: KF, output: Buffer): Buffer
}
