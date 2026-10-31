/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlin.test.*

// AES-CMAC -> [key size] -> [key] -> [signature]
abstract class AesCmacAlgorithmTest(cryptographyProvider: CryptographyProvider) :
    AesAlgorithmTest<AES.CMAC, AES.CMAC.Key, SignatureTestDataValidator>(
        provider = cryptographyProvider,
        algorithmId = AES.CMAC,
        algorithmLimitation = {
        when {
            provider.isApple || provider.isWebCrypto || provider.isCryptoKit
                -> fails("AES-CMAC is not supported")
            provider.isJdkDefault
                -> fails("AES-CMAC is supported only with BouncyCastle")
            else -> null
        }
    },
    ) {
    override fun TestValidatorScope.keyValidator(keys: List<AES.CMAC.Key>): SignatureTestDataValidator = signatures(
        verifiers = keys.map { it.signatureVerifier() },
        generators = keys.map { it.signatureGenerator() },
        signatureSizes = listOf(AES_BLOCK_SIZE),
        deterministic = true,
    )

    context(context: TestGenerationContext)
    override suspend fun SignatureTestDataValidator.generateRandom(key: AES.CMAC.Key, otherKey: AES.CMAC.Key) {
        generateSignatures(
            generator = key.signatureGenerator(),
            messageSizes = listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) },
        )
        otherKeySignature(otherKey.signatureGenerator())
    }

    context(context: TestGenerationContext)
    override suspend fun SignatureTestDataValidator.generateLarge(key: AES.CMAC.Key) {
        generateSignatures(key.signatureGenerator(), listOf(1_000_000))
    }

    // https://datatracker.ietf.org/doc/html/rfc4493#section-4 and NIST SP 800-38B
    @Test
    fun rfc4493() = test("rfc4493") {
        group(AesKeySizeTestParameters(AES.Key.Size.B128)) {
            encodableGroup(material(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c")), id = "rfc4493") {
                signature(
                    id = "Example1",
                    message = hex(""),
                    signature = hex("bb1d6929e95937287fa37d129b756746"),
                )
                signature(
                    id = "Example2",
                    message = hex("6bc1bee22e409f96e93d7e117393172a"),
                    signature = hex("070a16b46b4d4144f79bdd9dd04a287c"),
                )
                signature(
                    id = "Example3",
                    message = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
                    signature = hex("dfa66747de9ae63030ca32611497c827"),
                )
                signature(
                    id = "Example4",
                    message = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
                    signature = hex("51f0bebf7e3b9d92fc49741779363cfe"),
                )
            }
        }
        group(AesKeySizeTestParameters(AES.Key.Size.B256)) {
            encodableGroup(
                material(AES.Key.Format.RAW, hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")),
                id = "sp800-38b"
            ) {
                signature(
                    id = "Example1",
                    message = hex(""),
                    signature = hex("028962f61b7bf89efc6b551f4667d983"),
                )
            }
        }
    }
}
