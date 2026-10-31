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

// AES-ECB -> [key size] -> [key] -> [padding] -> [data]
abstract class AesEcbAlgorithmTest(cryptographyProvider: CryptographyProvider) : AesPaddingAlgorithmTest<AES.ECB, AES.ECB.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.ECB,
    algorithmLimitation = {
        when {
            provider.isWebCrypto || provider.isCryptoKit -> fails("AES-ECB is not supported")
            else                                         -> null
        }
    },
    ivSize = 0,
) {
    override fun cipher(key: AES.ECB.Key, padding: Boolean): Cipher = key.cipher(padding)

    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.1
    @Test
    fun sp80038a() = test("sp800-38a") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c")), id = "F.1.1") {
                group(AesPaddingTestParameters(padding = false)) {
                    ciphertext(
                        plaintext = hex("6bc1bee22e409f96e93d7e117393172a"),
                        ciphertext = hex("3ad77bb40d7a3660a89ecaf32466ef97"),
                    )
                }
            }
        }
    }
}
