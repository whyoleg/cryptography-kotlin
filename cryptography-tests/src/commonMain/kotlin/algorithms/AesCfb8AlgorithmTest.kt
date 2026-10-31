/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlin.test.*

// AES-CFB8 -> [key size] -> [key] -> [data]
abstract class AesCfb8AlgorithmTest(cryptographyProvider: CryptographyProvider) : AesStreamModeAlgorithmTest<AES.CFB8, AES.CFB8.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.CFB8,
    algorithmLimitation = {
        when {
            provider.isWebCrypto || provider.isCryptoKit -> fails("AES-CFB8 is not supported")
            else                                         -> null
        }
    },
) {
    override fun cipher(key: AES.CFB8.Key): IvCipher = key.cipher()

    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.3.7
    @Test
    fun sp80038a() = test("sp800-38a") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c")), id = "F.3.7") {
                ciphertext(
                    plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d"),
                    ciphertext = hex("3b79424c9c0dd436bace9e0ed4586a4f32b9"),
                    iv = hex("000102030405060708090a0b0c0d0e0f"),
                )
            }
        }
    }
}
