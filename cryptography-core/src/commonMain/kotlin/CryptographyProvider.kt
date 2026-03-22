/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

/**
 * Main entry point for obtaining cryptographic algorithm implementations.
 *
 * A provider wraps a specific cryptography backend (e.g., OpenSSL, JCA, WebCrypto, CryptoKit)
 * and returns algorithm instances configured for that backend.
 * Algorithm instances implement [CryptographyAlgorithm].
 * The global default provider is managed by [CryptographySystem].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyProvider {
    /**
     * The human-readable name identifying this provider (e.g., "JDK", "OpenSSL3").
     */
    public abstract val name: String

    /**
     * Looks up the algorithm matching [identifier] in this provider.
     *
     * Returns `null` if this provider does not support the requested algorithm.
     *
     * Use [get] when the algorithm is expected to be available.
     */
    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?

    /**
     * Looks up the algorithm matching [identifier] in this provider.
     *
     * Throws [IllegalStateException] if this provider does not support the requested algorithm.
     *
     * Use [getOrNull] to return null instead of throwing.
     */
    public open fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A =
        getOrNull(identifier) ?: throw IllegalStateException("Algorithm not found: $identifier")

    @Deprecated(
        "Replaced by CryptographySystem",
        level = DeprecationLevel.ERROR
    )
    @CryptographyProviderApi
    public object Registry {
        @Deprecated(
            "Use CryptographySystem::getRegisteredProviders",
            replaceWith = ReplaceWith(
                "CryptographySystem.getRegisteredProviders().asSequence()",
                "dev.whyoleg.cryptography.CryptographySystem"
            ),
            level = DeprecationLevel.ERROR
        )
        public val registeredProviders: Sequence<CryptographyProvider>
            get() = CryptographySystem.getRegisteredProviders().asSequence()

        @Deprecated(
            "Use CryptographySystem::registerProvider",
            replaceWith = ReplaceWith(
                "CryptographySystem.registerProvider(lazyOf(provider), 0)",
                "dev.whyoleg.cryptography.CryptographySystem"
            ),
            level = DeprecationLevel.ERROR
        )
        public fun registerProvider(provider: CryptographyProvider) {
            CryptographySystem.registerProvider(lazyOf(provider), 0)
        }

        @Deprecated(
            "Use CryptographySystem::registerProvider",
            replaceWith = ReplaceWith(
                "CryptographySystem.registerProvider(provider, 0)",
                "dev.whyoleg.cryptography.CryptographySystem"
            ),
            level = DeprecationLevel.ERROR
        )
        public fun registerProvider(provider: Lazy<CryptographyProvider>) {
            CryptographySystem.registerProvider(provider, 0)
        }
    }

    public companion object {
        /**
         * The default provider, automatically configured from registered providers.
         *
         * Resolved via [CryptographySystem.getDefaultProvider] from the registry if not explicitly set.
         */
        public val Default: CryptographyProvider get() = CryptographySystem.getDefaultProvider()
    }
}
