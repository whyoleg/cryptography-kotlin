/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyProvider {
    public abstract val name: String

    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?
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
        public val Default: CryptographyProvider get() = CryptographySystem.getDefaultProvider()
    }
}
