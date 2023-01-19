package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface CryptographyAlgorithm {
    public val id: CryptographyAlgorithmId<*>
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyAlgorithmId<A : CryptographyAlgorithm>(public val name: String)
