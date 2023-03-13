package dev.whyoleg.cryptography.provider

import dev.whyoleg.cryptography.algorithms.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyProvider {
    public abstract val name: String

    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?
    public open fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A =
        getOrNull(identifier) ?: throw CryptographyAlgorithmNotFoundException(identifier)

    public object Default : CryptographyProvider() {
        private val defaultProvider = defaultCryptographyProvider()
        override val name: String get() = defaultProvider.name
        override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? =
            defaultProvider.getOrNull(identifier)
    }

    public companion object
}

internal expect fun defaultCryptographyProvider(): CryptographyProvider
