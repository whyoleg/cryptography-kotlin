/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
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
    fun testSupported() = test {
        assertSupports(AES.ECB, !context.provider.isWebCrypto)
        assertSupports(AES.CBC)
        assertSupports(AES.CTR)
        assertSupports(AES.GCM, !context.provider.isApple)

        assertSupports(HMAC)

        assertSupports(MD5, !context.provider.isWebCrypto)
        assertSupports(SHA1)
        assertSupports(SHA224, !context.provider.isWebCrypto)
        assertSupports(SHA256)
        assertSupports(SHA384)
        assertSupports(SHA512)

        val supportsSha3 = !context.provider.isWebCrypto && !context.provider.isApple
        assertSupports(SHA3_224, supportsSha3)
        assertSupports(SHA3_256, supportsSha3)
        assertSupports(SHA3_384, supportsSha3)
        assertSupports(SHA3_512, supportsSha3)

        assertSupports(ECDSA)
        assertSupports(ECDH, !context.provider.isApple)

        assertSupports(RSA.PSS)
        assertSupports(RSA.OAEP)
        assertSupports(RSA.PKCS1)
        assertSupports(RSA.RAW, !context.provider.isWebCrypto)

        assertSupports(PBKDF2)
    }
}
