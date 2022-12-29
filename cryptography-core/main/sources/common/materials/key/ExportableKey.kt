package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.io.*

public interface ExportableKey<KF : KeyFormat> : Key {
    public suspend fun exportTo(format: KF): Buffer
    public suspend fun exportTo(format: KF, output: Buffer): Buffer
    public fun exportToBlocking(format: KF): Buffer
    public fun exportToBlocking(format: KF, output: Buffer): Buffer
}
