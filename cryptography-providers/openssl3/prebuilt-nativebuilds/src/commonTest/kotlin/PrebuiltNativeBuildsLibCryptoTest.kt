/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.prebuiltnativebuilds

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.test.*
import kotlinx.cinterop.*
import kotlin.test.*

class PrebuiltNativeBuildsLibCryptoTest : LibCrypto3Test() {

    @Test
    fun testExactVersion() {
        assertEquals("3.6.1", OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString())
        assertEquals(3, OPENSSL_version_major().toInt())
        assertEquals(6, OPENSSL_version_minor().toInt())
        assertEquals(1, OPENSSL_version_patch().toInt())
    }

}
