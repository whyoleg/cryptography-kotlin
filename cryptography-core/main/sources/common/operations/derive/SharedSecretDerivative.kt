package dev.whyoleg.cryptography.operations.derive

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.provider.*

//TODO: think about name a little more...
@SubclassOptInRequired(CryptographyProviderApi::class)
//key agreement
public interface SharedSecretDerivative<KF : KeyFormat> {
    public suspend fun deriveSharedSecretFrom(keyFormat: KF, keyInput: Buffer): Buffer
    public fun deriveSharedSecretFromBlocking(keyFormat: KF, keyInput: Buffer): Buffer
}
