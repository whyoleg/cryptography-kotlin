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

// AES-CBC -> [key size] -> [key] -> [padding] -> [data]
abstract class AesCbcAlgorithmTest(cryptographyProvider: CryptographyProvider) : AesPaddingAlgorithmTest<AES.CBC, AES.CBC.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.CBC,
    algorithmLimitation = {
        when {
            provider.isCryptoKit -> fails("AES-CBC is not supported")
            else                 -> null
        }
    },
    ivSize = AES_BLOCK_SIZE,
) {
    override fun cipher(key: AES.CBC.Key, padding: Boolean): Cipher = key.cipher(padding)

    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.2.1
    @Test
    fun sp80038a() = test("sp800-38a") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c")), id = "F.2.1") {
                group(AesPaddingTestParameters(padding = false)) {
                    ciphertext(
                        plaintext = hex("6bc1bee22e409f96e93d7e117393172a"),
                        ciphertext = hex("7649abac8119b246cee98e9b12e9197d"),
                        iv = hex("000102030405060708090a0b0c0d0e0f"),
                    )
                }
            }
        }
    }
}
