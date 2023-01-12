package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public suspend fun hash(dataInput: Buffer): Buffer
    public fun hashBlocking(dataInput: Buffer): Buffer
}
