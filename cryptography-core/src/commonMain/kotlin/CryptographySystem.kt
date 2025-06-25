/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.random.*

// thread-unsafe, mutations should be used only during APP initialzation if needed
public object CryptographySystem {
    private val impl = CryptographySystemImpl()

    init {
        loadProviders()
    }

    // can be called at-most-once before calling `getDefaultProvider`
    public fun setDefaultProvider(provider: CryptographyProvider): Unit = impl.setDefaultProvider(provider)
    public fun getDefaultProvider(): CryptographyProvider = impl.getDefaultProvider()

    // lower priority is better
    public fun registerProvider(provider: Lazy<CryptographyProvider>, priority: Int): Unit = impl.registerProvider(provider, priority)
    public fun getRegisteredProviders(): List<CryptographyProvider> = impl.getRegisteredProviders()

    public fun setDefaultRandom(random: CryptographyRandom): Unit = impl.setDefaultRandom(random)
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
