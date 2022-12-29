package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.io.*

public interface KeyImporter<KF : KeyFormat, K : Key> {
    public suspend fun importFrom(format: KF, input: Buffer): K
    public fun importFromBlocking(format: KF, input: Buffer): K
}
