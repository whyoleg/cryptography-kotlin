package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SHAKE : CryptographyAlgorithm {
    public fun hasher(digestSize: BinarySize): Hasher

    public object B128 : CryptographyAlgorithmId<SHAKE>("SHAKE-128")
    public object B256 : CryptographyAlgorithmId<SHAKE>("SHAKE-256")
}
