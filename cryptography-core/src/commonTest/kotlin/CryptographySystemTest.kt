/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import kotlin.test.*

@OptIn(CryptographyProviderApi::class)
class CryptographySystemTest {
    private fun testSystem(block: (system: CryptographySystemImpl) -> Unit) = block(CryptographySystemImpl())

    @Test
    fun registerProviderThrowsErrorWhenPriorityIsDuplicated() = testSystem { system ->
        val provider1 = TestCryptographyProvider("Provider1")
        val provider2 = TestCryptographyProvider("Provider2")
        system.registerProvider(lazyOf(provider1), priority = 0)

        val exception = assertFailsWith<IllegalArgumentException> {
            system.registerProvider(lazyOf(provider2), priority = 0)
        }
        assertEquals(
            "Provider with priority 0 already registered. Every registered provider should have unique priority.",
            exception.message
        )
    }

    @Test
    fun registerProviderThrowsErrorWhenProviderIsAlreadyAccessed() = testSystem { system ->
        val provider1 = TestCryptographyProvider("Provider1")
        system.registerProvider(lazyOf(provider1), priority = 0)
        system.getDefaultProvider()

        val provider2 = TestCryptographyProvider("Provider2")
        val exception = assertFailsWith<IllegalStateException> {
            system.registerProvider(lazyOf(provider2), priority = 1)
        }
        assertEquals("Cannot register provider after `getRegisteredProviders` was called", exception.message)
    }

    @Test
    fun registerProviderInitializesLazyProviderOnlyWhenAccessed() = testSystem { system ->
        var initialized = false
        val lazyProvider = lazy {
            initialized = true
            TestCryptographyProvider("LazyProvider")
        }
        system.registerProvider(lazyProvider, priority = 0)
        assertFalse(initialized)

        system.getDefaultProvider()
        assertTrue(initialized)
    }

    @Test
    fun registerProviderThrowsErrorWhenPriorityIsNegative() = testSystem { system ->
        val provider = TestCryptographyProvider("Provider")
        val exception = assertFailsWith<IllegalArgumentException> {
            system.registerProvider(lazyOf(provider), priority = -1)
        }
        assertEquals("Priority must be greater or equal to 0", exception.message)
    }

    @Test
    fun getDefaultProviderThrowsErrorWhenNoProvidersAreRegistered() = testSystem { system ->
        val exception = assertFailsWith<IllegalStateException> {
            system.getDefaultProvider()
        }
        assertEquals("No providers registered. Please provide a dependency or register provider explicitly", exception.message)
    }

    @Test
    fun getDefaultProviderReturnsSingleRegisteredProviderWhenOneProviderIsRegistered() = testSystem { system ->
        val provider = TestCryptographyProvider("Provider1")
        system.registerProvider(lazyOf(provider), priority = 0)

        val defaultProvider = system.getDefaultProvider()

        assertEquals("Provider1", defaultProvider.name)
    }

    @Test
    fun getDefaultProviderReturnsCompositeProviderWhenMultipleProvidersAreRegistered() = testSystem { system ->
        val provider1 = TestCryptographyProvider("Provider1")
        val provider2 = TestCryptographyProvider("Provider2")
        system.registerProvider(lazyOf(provider1), priority = 0)
        system.registerProvider(lazyOf(provider2), priority = 1)

        val defaultProvider = system.getDefaultProvider()

        assertEquals("Composite(Provider1,Provider2)", defaultProvider.name)
    }

    @Test
    fun getDefaultProviderReturnsExplicitlySetProvider() = testSystem { system ->
        val provider = TestCryptographyProvider("ExplicitProvider")
        system.setDefaultProvider(provider)

        val defaultProvider = system.getDefaultProvider()

        assertEquals("ExplicitProvider", defaultProvider.name)
    }

    @Test
    fun setDefaultProviderThrowsErrorIfProviderIsAlreadySet() = testSystem { system ->
        val provider = TestCryptographyProvider("ExplicitProvider")
        system.setDefaultProvider(provider)

        val exception = assertFailsWith<IllegalStateException> {
            system.setDefaultProvider(provider)
        }
        assertEquals("Default provider already set", exception.message)
    }

    @Test
    fun setDefaultProviderThrowsErrorIfProviderIsAlreadyAccessed() = testSystem { system ->
        val provider = TestCryptographyProvider("ExplicitProvider")
        system.registerProvider(lazyOf(provider), priority = 0)

        assertEquals(system.getDefaultProvider().name, "ExplicitProvider")

        val exception = assertFailsWith<IllegalStateException> {
            system.setDefaultProvider(provider)
        }
        assertEquals("Cannot set default provider after `getDefaultProvider` was called", exception.message)
    }

    @Test
    fun getDefaultProviderEnsuresProviderPriorityOrderIsRespected() = testSystem { system ->
        val provider1 = TestCryptographyProvider("Provider1")
        val provider2 = TestCryptographyProvider("Provider2")
        system.registerProvider(lazyOf(provider2), priority = 1)
        system.registerProvider(lazyOf(provider1), priority = 0)

        val defaultProvider = system.getDefaultProvider()

        assertEquals("Composite(Provider1,Provider2)", defaultProvider.name)
    }

    @Test
    fun compositeProviderResolvesAlgorithmsBasedOnPriority() = testSystem { system ->
        val aId = TestAlgorithmId("A")
        val aImpl1 = TestAlgorithm(aId)
        val aImpl2 = TestAlgorithm(aId)
        val provider1 = TestCryptographyProvider("Provider1", mapOf(aId to aImpl1))
        val provider2 = TestCryptographyProvider("Provider2", mapOf(aId to aImpl2))
        system.registerProvider(lazyOf(provider1), priority = 1)
        system.registerProvider(lazyOf(provider2), priority = 0)

        val defaultProvider = system.getDefaultProvider()
        assertEquals("Composite(Provider2,Provider1)", defaultProvider.name)
        assertEquals(aImpl2, defaultProvider.getOrNull(aId))
    }

    @Test
    fun compositeProviderResolvesAlgorithmsFromBothProviders() = testSystem { system ->
        val aId = TestAlgorithmId("A")
        val bId = TestAlgorithmId("B")
        val aImpl1 = TestAlgorithm(aId)
        val bImpl2 = TestAlgorithm(bId)
        val provider1 = TestCryptographyProvider("Provider1", mapOf(aId to aImpl1))
        val provider2 = TestCryptographyProvider("Provider2", mapOf(bId to bImpl2))
        system.registerProvider(lazyOf(provider1), priority = 1)
        system.registerProvider(lazyOf(provider2), priority = 0)

        val defaultProvider = system.getDefaultProvider()
        assertEquals("Composite(Provider2,Provider1)", defaultProvider.name)
        assertEquals(aImpl1, defaultProvider.getOrNull(aId))
        assertEquals(bImpl2, defaultProvider.getOrNull(bId))
    }

    @Test
    fun compositeProviderReturnsNullWhenNoProvidersResolveAlgorithm() = testSystem { system ->
        val aId = TestAlgorithmId("A")
        val provider1 = TestCryptographyProvider("Provider1", emptyMap())
        val provider2 = TestCryptographyProvider("Provider2", emptyMap())
        system.registerProvider(lazyOf(provider1), priority = 1)
        system.registerProvider(lazyOf(provider2), priority = 0)

        val defaultProvider = system.getDefaultProvider()
        assertEquals("Composite(Provider2,Provider1)", defaultProvider.name)
        assertNull(defaultProvider.getOrNull(aId))
    }

    class TestCryptographyProvider(
        override val name: String,
        private val algorithms: Map<CryptographyAlgorithmId<*>, TestAlgorithm> = emptyMap(),
    ) : CryptographyProvider() {
        override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? {
            @Suppress("UNCHECKED_CAST")
            return algorithms[identifier] as? A
        }
    }

    class TestAlgorithm(override val id: CryptographyAlgorithmId<*>) : CryptographyAlgorithm

    class TestAlgorithmId(name: String) : CryptographyAlgorithmId<TestAlgorithm>(name)
}
