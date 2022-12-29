package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public interface CryptographyAlgorithm

@SubclassOptInRequired(ProviderApi::class)
public abstract class CryptographyAlgorithmId<A : CryptographyAlgorithm>
