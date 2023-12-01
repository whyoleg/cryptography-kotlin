/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyProvider {
    public abstract val name: String

    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?
    public open fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A =
        getOrNull(identifier) ?: throw CryptographyAlgorithmNotFoundException(identifier)

    @CryptographyProviderApi
    public object Registry {
        // TODO: make this thread safe (just synchronized will be enough)
        private val providers = initProviders().toMutableList()
        public val registeredProviders: Sequence<CryptographyProvider>
            get() = providers.toList().asSequence().map(Lazy<CryptographyProvider>::value)

        public fun registerProvider(provider: CryptographyProvider) {
            providers.add(lazyOf(provider))
        }

        public fun registerProvider(provider: Lazy<CryptographyProvider>) {
            providers.add(provider)
        }
    }

    public companion object {
        public val Default: CryptographyProvider by lazy {
            @OptIn(CryptographyProviderApi::class)
            checkNotNull(Registry.registeredProviders.firstOrNull()) {
                "No providers registered. Please provide a dependency or register provider explicitly"
            }
        }
    }
}

// used only on JVM for ServiceLoader
internal expect fun initProviders(): List<Lazy<CryptographyProvider>>
