/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

abstract class SupportedAlgorithmsTest(provider: CryptographyProvider) : ProviderTest(provider) {

    private fun ProviderTestScope.assertSupports(
        algorithmId: CryptographyAlgorithmId<*>,
        supported: Boolean = true,
    ) {
        val algorithm = provider.getOrNull(algorithmId)
        when {
            supported -> assertNotNull(algorithm, "Algorithm ${algorithmId.name} is not supported by ${provider.name} provider")
            else      -> assertNull(algorithm, "Algorithm ${algorithmId.name} is supported by ${provider.name} provider")
        }
    }

    @Test
    fun testSupported() = testWithProvider {

        assertSupports(AES.ECB, !context.provider.isWebCrypto && !context.provider.isCryptoKit)
        assertSupports(AES.CBC, !context.provider.isCryptoKit)
        assertSupports(AES.CMAC, !context.provider.isApple && !context.provider.isWebCrypto && !context.provider.isCryptoKit)
        assertSupports(AES.CTR, !context.provider.isCryptoKit)
        assertSupports(AES.GCM, !context.provider.isApple)

        assertSupports(HMAC)

        assertSupports(MD5, !context.provider.isWebCrypto)
        assertSupports(SHA1)
        assertSupports(SHA224, !context.provider.isWebCrypto && !context.provider.isCryptoKit)
        assertSupports(SHA256)
        assertSupports(SHA384)
        assertSupports(SHA512)

        val supportsSha3 = !context.provider.isWebCrypto && !context.provider.isApple && !context.provider.isCryptoKit
        assertSupports(SHA3_224, supportsSha3)
        assertSupports(SHA3_256, supportsSha3)
        assertSupports(SHA3_384, supportsSha3)
        assertSupports(SHA3_512, supportsSha3)

        assertSupports(RIPEMD160, !context.provider.isApple && !context.provider.isWebCrypto && !context.provider.isCryptoKit)

        assertSupports(ECDSA)
        assertSupports(ECDH, !context.provider.isApple)

        // Edwards-family
        assertSupports(EdDSA, !context.provider.isApple)
        assertSupports(XDH, !context.provider.isApple)

        assertSupports(RSA.PSS, !context.provider.isCryptoKit)
        assertSupports(RSA.OAEP, !context.provider.isCryptoKit)
        assertSupports(RSA.PKCS1, !context.provider.isCryptoKit)
        assertSupports(RSA.RAW, !context.provider.isWebCrypto && !context.provider.isCryptoKit)

        assertSupports(PBKDF2, !context.provider.isCryptoKit)
        assertSupports(HKDF)
    }
}
