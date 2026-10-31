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

// AES-GCM -> [key size] -> [key] -> [tag size] -> [data]
abstract class AesGcmAlgorithmTest(cryptographyProvider: CryptographyProvider) : AesAeadAlgorithmTest<AES.GCM, AES.GCM.Key>(
    provider = cryptographyProvider,
    algorithmId = AES.GCM,
    algorithmLimitation = {
        when {
            provider.isApple -> fails("AES-GCM is not supported")
            else             -> null
        }
    },
    tagSizes = listOf(96, 104, 112, 120, 128),
    ivSizes = listOf(12, 14, 16),
) {
    override fun cipher(key: AES.GCM.Key, tagSize: BinarySize): IvAuthenticatedCipher = key.cipher(tagSize)

    override fun TestLimitationScope.tagSizeLimitation(tagSizeBits: Int): TestLimitation? = when {
        // fails when creating ciphers
        tagSizeBits != 128 && provider.isCryptoKit -> fails("Only 128 bits tag is supported")
        else                                       -> null
    }

    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf (Test Case 1, 2)
    @Test
    fun gcmSpec() = test("gcm-spec") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("00000000000000000000000000000000")), id = "zero-key") {
                group(AesTagSizeTestParameters(128)) {
                    ciphertext(
                        id = "TestCase1",
                        plaintext = hex(""),
                        ciphertext = hex("58e2fccefa7e3061367f1d57a4e7455a"),
                        iv = hex("000000000000000000000000"),
                    )
                    ciphertext(
                        id = "TestCase2",
                        plaintext = hex("00000000000000000000000000000000"),
                        ciphertext = hex("0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf"),
                        iv = hex("000000000000000000000000"),
                    )
                }
            }
        }
    }
}
