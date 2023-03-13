package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface KeyGenerator<K : Key> {
    public suspend fun generateKey(): K = generateKeyBlocking()
    public fun generateKeyBlocking(): K
}
