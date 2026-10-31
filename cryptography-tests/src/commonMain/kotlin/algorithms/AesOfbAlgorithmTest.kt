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

// AES-OFB -> [key size] -> [key] -> [data]
abstract class AesOfbAlgorithmTest(cryptographyProvider: CryptographyProvider) : AesStreamModeAlgorithmTest<AES.OFB, AES.OFB.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.OFB,
    algorithmLimitation = {
        when {
            provider.isWebCrypto || provider.isCryptoKit -> fails("AES-OFB is not supported")
            else                                         -> null
        }
    },
) {
    override fun cipher(key: AES.OFB.Key): IvCipher = key.cipher()

    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.4.1
    @Test
    fun sp80038a() = test("sp800-38a") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c")), id = "F.4.1") {
                ciphertext(
                    plaintext = hex("6bc1bee22e409f96e93d7e117393172a"),
                    ciphertext = hex("3b3fd92eb72dad20333449f8e83cfb4a"),
                    iv = hex("000102030405060708090a0b0c0d0e0f"),
                )
            }
        }
    }
}
