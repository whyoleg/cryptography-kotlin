/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.random.*

/**
 * Manages global cryptography configuration: the default provider, provider registry, and default random.
 *
 * Mutations ([setDefaultProvider], [registerProvider], [setDefaultRandom]) should only be called
 * during application initialization before any cryptographic operations.
 * This object is not thread-safe for mutations.
 */
public object CryptographySystem {
    private val impl = CryptographySystemImpl()

    init {
        loadProviders()
    }

    /**
     * Overrides the default provider with the given [provider].
     *
     * Must be called at most once and before any call to [getDefaultProvider],
     * otherwise an [IllegalStateException] is thrown.
     *
     * Use [getDefaultProvider] to retrieve the provider configured here or resolved from the registry.
     */
    public fun setDefaultProvider(provider: CryptographyProvider): Unit = impl.setDefaultProvider(provider)

    /**
     * Returns the default [CryptographyProvider], resolving it on first access.
     *
     * If [setDefaultProvider] was called, that provider is used.
     * Otherwise, the provider is resolved from the registry:
     * a single registered provider is used directly,
     * and multiple registered providers are combined into a composite that
     * queries each in priority order.
     *
     * Throws [IllegalStateException] if no providers are registered and none was set explicitly.
     *
     * Use [setDefaultProvider] to override the resolved provider.
     * Use [registerProvider] to add providers to the registry.
     */
    public fun getDefaultProvider(): CryptographyProvider = impl.getDefaultProvider()

    /**
     * Adds a lazily-initialized provider to the global registry with the given [priority].
     *
     * Lower [priority] values indicate higher precedence.
     * Each registered provider must have a unique priority.
     * Must be called before any call to [getRegisteredProviders] or [getDefaultProvider].
     *
     * Use [getRegisteredProviders] to retrieve all registered providers sorted by priority.
     * Use [getDefaultProvider] to resolve the default provider from the registry.
     */
    public fun registerProvider(provider: Lazy<CryptographyProvider>, priority: Int): Unit = impl.registerProvider(provider, priority)

    /**
     * Returns all registered providers sorted by priority (lowest first).
     *
     * The list is computed once on first access; subsequent calls to [registerProvider]
     * after this point will throw.
     *
     * Use [registerProvider] to add providers to the registry before this is called.
     */
    public fun getRegisteredProviders(): List<CryptographyProvider> = impl.getRegisteredProviders()

    /**
     * Overrides the default random source with the given [random].
     *
     * Must be called at most once and before any call to [getDefaultRandom],
     * otherwise an [IllegalStateException] is thrown.
     *
     * Use [getDefaultRandom] to retrieve the random source configured here or the platform default.
     */
    public fun setDefaultRandom(random: CryptographyRandom): Unit = impl.setDefaultRandom(random)

    /**
     * Returns the default [CryptographyRandom] source, resolving it on first access.
     *
     * If [setDefaultRandom] was called, that source is used.
     * Otherwise, the platform-specific default random is used.
     *
     * Use [setDefaultRandom] to override the default random source.
     */
    public fun getDefaultRandom(): CryptographyRandom = impl.getDefaultRandom()
}

// to be able to test this
internal class CryptographySystemImpl {
    // priority -> provider
    private val registeredProviders = mutableMapOf<Int, Lazy<CryptographyProvider>>()
    private val lazyRegisteredProviders = lazy {
        registeredProviders.entries.sortedBy { it.key }.map { it.value.value }
    }

    private var defaultProvider: CryptographyProvider? = null
    private val lazyDefaultProvider = lazy {
        defaultProvider ?: lazyRegisteredProviders.value.let {
            when (it.size) {
                0    -> error("No providers registered. Please provide a dependency or register provider explicitly")
                1    -> it.first()
                else -> CompositeProvider(it)
            }
        }
    }

    private var defaultRandom: CryptographyRandom? = null
    private val lazyDefaultRandom = lazy {
        defaultRandom ?: CryptographyRandom.Default
    }

    fun getDefaultProvider(): CryptographyProvider = lazyDefaultProvider.value

    // can be called at-most-once before calling `getDefaultProvider`
    fun setDefaultProvider(provider: CryptographyProvider) {
        check(!lazyDefaultProvider.isInitialized()) { "Cannot set default provider after `getDefaultProvider` was called" }
        check(defaultProvider == null) { "Default provider already set" }

        defaultProvider = provider
    }

    fun getRegisteredProviders(): List<CryptographyProvider> = lazyRegisteredProviders.value

    // lower priority is better
    fun registerProvider(provider: Lazy<CryptographyProvider>, priority: Int) {
        require(priority >= 0) { "Priority must be greater or equal to 0" }
        require(priority !in registeredProviders) {
            "Provider with priority $priority already registered. Every registered provider should have unique priority."
        }

        check(!lazyRegisteredProviders.isInitialized()) {
            "Cannot register provider after `getRegisteredProviders` was called"
        }

        registeredProviders[priority] = provider
    }

    fun setDefaultRandom(random: CryptographyRandom) {
        check(!lazyDefaultRandom.isInitialized()) { "Cannot set default random after `getDefaultRandom` was called" }
        check(defaultRandom == null) { "Default random already set" }

        defaultRandom = random
    }

    fun getDefaultRandom(): CryptographyRandom = lazyDefaultRandom.value

    @OptIn(CryptographyProviderApi::class)
    private class CompositeProvider(
        private val providers: List<CryptographyProvider>,
    ) : CryptographyProvider() {
        override val name: String
            get() = providers.joinToString(
                prefix = "Composite(", separator = ",", postfix = ")",
                transform = CryptographyProvider::name
            )

        override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? {
            return providers.firstNotNullOfOrNull { it.getOrNull(identifier) }
        }
    }
}

// used only on JVM for ServiceLoader
internal expect fun CryptographySystem.loadProviders()
