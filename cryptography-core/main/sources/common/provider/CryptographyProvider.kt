package dev.whyoleg.cryptography.provider

import dev.whyoleg.cryptography.algorithms.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyProvider(
    public val name: String,
) {
    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?
    public open fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A =
        getOrNull(identifier) ?: throw CryptographyAlgorithmNotFoundException(identifier)

    public companion object
}
