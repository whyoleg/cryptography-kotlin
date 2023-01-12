package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyDecoder<KF : KeyFormat, K : Key> {
    public suspend fun decodeFrom(format: KF, input: Buffer): K
    public fun decodeFromBlocking(format: KF, input: Buffer): K
}
