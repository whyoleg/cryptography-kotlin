/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.tests.*

// AES-CCM -> [key size] -> [key] -> [tag size] -> [data]
abstract class AesCcmAlgorithmTest(cryptographyProvider: CryptographyProvider) : AesAeadAlgorithmTest<AES.CCM, AES.CCM.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.CCM,
    algorithmLimitation = {
        when {
            provider.isApple || provider.isWebCrypto || provider.isCryptoKit
                 -> fails("AES-CCM is not supported")
            provider.isJdkDefault
                -> fails("AES-CCM is supported only with BouncyCastle")
            else -> null
        }
    },
    tagSizes = listOf(32, 48, 64, 80, 96, 112, 128),
    ivSizes = listOf(7, 8, 10, 13),
) {
    override fun cipher(key: AES.CCM.Key, tagSize: BinarySize): IvAuthenticatedCipher = key.cipher(tagSize)
}
