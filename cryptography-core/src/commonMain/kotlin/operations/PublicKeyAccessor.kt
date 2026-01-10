package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PublicKeyAccessor<PublicK : Key> {
    public suspend fun getPublicKey(): PublicK = getPublicKeyBlocking()
    public fun getPublicKeyBlocking(): PublicK
}
