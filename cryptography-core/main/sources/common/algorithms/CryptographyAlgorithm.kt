package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public interface CryptographyAlgorithm {
    //TODO: add some name? or id?
}

@SubclassOptInRequired(ProviderApi::class)
public abstract class CryptographyAlgorithmId<A : CryptographyAlgorithm> {
    //TODO: add some name?
}
