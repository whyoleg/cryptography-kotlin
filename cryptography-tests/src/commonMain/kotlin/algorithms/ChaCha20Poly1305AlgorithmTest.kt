/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlin.test.*

typealias ChaCha20Poly1305TestGroupValidator = EncodableTestGroupValidator<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key, CipherTestDataValidator>

// ChaCha20-Poly1305 -> [key] -> [data]
abstract class ChaCha20Poly1305AlgorithmTest(cryptographyProvider: CryptographyProvider) :
    AlgorithmTest<ChaCha20Poly1305, ChaCha20Poly1305TestGroupValidator>(
        provider = cryptographyProvider,
        algorithmId = ChaCha20Poly1305,
        algorithmLimitation = {
            when {
                provider.isApple || provider.isWebCrypto
                     -> fails("ChaCha20-Poly1305 is not supported")
                provider.isJdkDefault && platform.isJdk { major < 11 }
                    -> fails("ChaCha20-Poly1305 is supported only since JDK 11 or with BouncyCastle")
                else -> null
            }
        },
    ) {
    override fun TestValidatorScope.validator(algorithm: ChaCha20Poly1305): ChaCha20Poly1305TestGroupValidator = encodables(
        decoder = algorithm.keyDecoder(),
        formats = {
            raw(ChaCha20Poly1305.Key.Format.RAW, size = KEY_SIZE)
            jwk(ChaCha20Poly1305.Key.Format.JWK, "kty", "k")
        },
    ) { keys ->
        val ciphers = keys.map { it.cipher() }
        ciphertexts(
            encryptors = ciphers,
            decryptors = ciphers,
            ivSize = IV_SIZE,
            ciphertextSize = { it + TAG_SIZE },
            deterministic = false,
        )
    }

    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    @Test
    fun rfc8439() = test("rfc8439") {
        encodableGroup(
            material(ChaCha20Poly1305.Key.Format.RAW, hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")),
            id = "2.8.2",
        ) {
            ciphertext(
                plaintext = text("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
                ciphertext = hex(
                    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" +
                            "1ae10b594f09e26a7e902ecbd0600691"
                ),
                iv = hex("070000004041424344454647"),
                associatedData = hex("50515253c0c1c2c3c4c5c6c7"),
            )
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        generateEncodableGroups(algorithm.keyGenerator(), iterations = 2) { key ->
            val cipher = key.cipher()
            generateCiphertexts(cipher, listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) })
            generateCiphertexts(
                encryptor = cipher,
                plaintextSizes = listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) },
                associatedDataSize = 100,
            )
            generateCiphertexts(cipher, listOf(0, 16, 1000), ivSize = IV_SIZE)
            generateCiphertexts(cipher, listOf(0, 16, 1000), ivSize = IV_SIZE, associatedDataSize = 16)
            // shorter than IV + tag
            invalidCiphertexts(0, IV_SIZE + TAG_SIZE - 1)
            otherKeyCiphertext(algorithm.keyGenerator().generateKey().cipher())
        }
        // large data is stored and validated by every provider, so it's generated only for a single key
        generateEncodableGroups(algorithm.keyGenerator(), iterations = 1) { key ->
            generateCiphertexts(key.cipher(), listOf(1_000_000), associatedDataSize = 100)
        }
    }
}

private const val KEY_SIZE = 32
private const val IV_SIZE = 12
private const val TAG_SIZE = 16
