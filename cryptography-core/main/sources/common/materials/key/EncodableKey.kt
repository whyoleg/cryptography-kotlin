package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key {
    public suspend fun encodeTo(format: KF): Buffer = encodeToBlocking(format)
    public fun encodeToBlocking(format: KF): Buffer
}
