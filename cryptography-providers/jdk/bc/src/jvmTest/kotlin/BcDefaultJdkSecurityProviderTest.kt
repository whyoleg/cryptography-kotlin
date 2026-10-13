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
    fun scryptRequiresSelectedBouncyCastleProvider() {
        val nonBouncyCastleProvider = Security.getProviders().first { it.name != "BC" }
        assertNull(CryptographyProvider.JDK(nonBouncyCastleProvider).getOrNull(Scrypt))

        val bouncyCastleProvider = ServiceLoader.load(DefaultJdkSecurityProvider::class.java).single().provider.value
        assertNotNull(CryptographyProvider.JDK(bouncyCastleProvider).getOrNull(Scrypt))
    }

    @Test
    fun allProvidersExposeScryptWhenBouncyCastleIsRegistered() {
        val bouncyCastleProvider = ServiceLoader.load(DefaultJdkSecurityProvider::class.java).single().provider.value
        val wasRegistered = Security.getProvider(bouncyCastleProvider.name) != null
        if (!wasRegistered) Security.addProvider(bouncyCastleProvider)
        try {
            assertNotNull(CryptographyProvider.JDK().getOrNull(Scrypt))
        } finally {
            if (!wasRegistered) Security.removeProvider(bouncyCastleProvider.name)
        }
    }
}
