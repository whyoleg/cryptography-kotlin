/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.bc

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.*
import java.util.*
import kotlin.test.*

class BcDefaultJdkSecurityProviderTest {
    @Test
    fun testProviderName() {
        assertEquals(CryptographyProvider.JDK.name, "JDK (BC)")
    }

    @Test
    fun bouncyCastleOnlyAlgorithmsRequireSelectedBouncyCastleProvider() {
        val nonBouncyCastleProvider = Security.getProviders().first { it.name != "BC" }
        val nonBouncyCastle = CryptographyProvider.JDK(nonBouncyCastleProvider)
        assertNull(nonBouncyCastle.getOrNull(Scrypt))
        assertNull(nonBouncyCastle.getOrNull(SHAKE256))

        val bouncyCastleProvider = ServiceLoader.load(DefaultJdkSecurityProvider::class.java).single().provider.value
        val bouncyCastle = CryptographyProvider.JDK(bouncyCastleProvider)
        assertNotNull(bouncyCastle.getOrNull(Scrypt))
        assertNotNull(bouncyCastle.getOrNull(SHAKE256))
    }

    @Test
    fun allProvidersExposeBouncyCastleOnlyAlgorithmsWhenBouncyCastleIsRegistered() {
        val bouncyCastleProvider = ServiceLoader.load(DefaultJdkSecurityProvider::class.java).single().provider.value
        val wasRegistered = Security.getProvider(bouncyCastleProvider.name) != null
        if (!wasRegistered) Security.addProvider(bouncyCastleProvider)
        try {
            val provider = CryptographyProvider.JDK()
            assertNotNull(provider.getOrNull(Scrypt))
            assertNotNull(provider.getOrNull(SHAKE256))
        } finally {
            if (!wasRegistered) Security.removeProvider(bouncyCastleProvider.name)
        }
    }
}
