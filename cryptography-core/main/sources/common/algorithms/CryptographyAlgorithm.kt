package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface CryptographyAlgorithm {
    //TODO: add some name? or id?
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyAlgorithmId<A : CryptographyAlgorithm> {
    //TODO: add some name?
}
