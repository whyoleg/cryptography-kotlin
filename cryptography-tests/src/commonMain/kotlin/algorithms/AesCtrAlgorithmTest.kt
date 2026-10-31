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

// AES-CTR -> [key size] -> [key] -> [data]
abstract class AesCtrAlgorithmTest(cryptographyProvider: CryptographyProvider) : AesStreamModeAlgorithmTest<AES.CTR, AES.CTR.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.CTR,
    algorithmLimitation = {
        when {
            provider.isCryptoKit -> fails("AES-CTR is not supported")
            else                 -> null
        }
    },
) {
    override fun cipher(key: AES.CTR.Key): IvCipher = key.cipher()

    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.5.1
    @Test
    fun sp80038a() = test("sp800-38a") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c")), id = "F.5.1") {
                ciphertext(
                    plaintext = hex("6bc1bee22e409f96e93d7e117393172a"),
                    ciphertext = hex("874d6191b620e3261bef6864990db6ce"),
                    iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                )
            }
        }
    }
}
