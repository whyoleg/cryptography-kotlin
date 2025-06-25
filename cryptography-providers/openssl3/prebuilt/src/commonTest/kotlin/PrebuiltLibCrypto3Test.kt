/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.prebuilt

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.test.*
import kotlinx.cinterop.*
import kotlin.test.*

class PrebuiltLibCrypto3Test : LibCrypto3Test() {

    @Test
    fun testExactVersion() {
        assertEquals("3.5.0", OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString())
        assertEquals(3, OPENSSL_version_major().toInt())
        assertEquals(5, OPENSSL_version_minor().toInt())
        assertEquals(0, OPENSSL_version_patch().toInt())
    }

}
