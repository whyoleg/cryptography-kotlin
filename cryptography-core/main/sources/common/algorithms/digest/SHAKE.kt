package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public abstract class SHAKE : CryptographyAlgorithm {
    public abstract fun hasher(digestSize: BinarySize): Hasher

    public object B128 : CryptographyAlgorithmId<SHAKE>()
    public object B256 : CryptographyAlgorithmId<SHAKE>()
}
