package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableKey<KF : KeyFormat> : Key {
    public suspend fun encodeTo(format: KF): ByteArray = encodeToBlocking(format)
    public fun encodeToBlocking(format: KF): ByteArray
}
