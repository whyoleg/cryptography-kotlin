/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

typealias HmacTestGroupValidator = TestGroupValidator<HmacTestParameters, HmacKeyTestGroupValidator>
typealias HmacKeyTestGroupValidator = EncodableTestGroupValidator<HMAC.Key.Format, HMAC.Key, SignatureTestDataValidator>

@Serializable
data class HmacTestParameters(val digest: SerializableDigest) : TestParameters {
    override val id: String get() = digest.name
}

// HMAC -> [digest] -> [key] -> [signature]
abstract class HmacAlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<HMAC, HmacTestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = HMAC,
) {
    override fun TestValidatorScope.validator(algorithm: HMAC): HmacTestGroupValidator = group<HmacTestParameters, _>(
        // all providers fail when creating decoders and generators
        limitation = { (digest) -> failsIfSignatureDigestUnsupported(digest) },
    ) { (digest) ->
        encodables(
            decoder = algorithm.keyDecoder(digest),
            formats = {
                raw(HMAC.Key.Format.RAW)
                jwk(HMAC.Key.Format.JWK, "kty", "k")
            },
        ) { keys ->
            signatures(
                verifiers = keys.map { it.signatureVerifier() },
                generators = keys.map { it.signatureGenerator() },
                signatureSizes = listOf(digest.digestSize),
                deterministic = true,
            )
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc4231#section-4
    @Test
    fun rfc4231() = test("rfc4231") {
        fun key(value: ByteString): TestMaterial<HMAC.Key.Format> = material(HMAC.Key.Format.RAW, value)

        // keys and data are the same for all digests
        val key1 = hex("0b".repeat(20))
        val data1 = text("Hi There")
        val key2 = text("Jefe")
        val data2 = text("what do ya want for nothing?")
        val key3 = hex("aa".repeat(20))
        val data3 = hex("dd".repeat(50))
        val key4 = hex("0102030405060708090a0b0c0d0e0f10111213141516171819")
        val data4 = hex("cd".repeat(50))
        val key5 = hex("0c".repeat(20))
        val data5 = text("Test With Truncation")
        // used by test cases 6 and 7
        val key6 = hex("aa".repeat(131))
        val data6 = text("Test Using Larger Than Block-Size Key - Hash Key First")
        val data7 = text(
            "This is a test using a larger than block-size key and a larger than block-size data. " +
                    "The key needs to be hashed before being used by the HMAC algorithm."
        )

        group(HmacTestParameters(SHA224)) {
            encodableGroup(key(key1), id = "TestCase1") {
                signature(data1, hex("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"))
            }
            encodableGroup(key(key2), id = "TestCase2") {
                signature(data2, hex("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"))
            }
            encodableGroup(key(key3), id = "TestCase3") {
                signature(data3, hex("7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"))
            }
            encodableGroup(key(key4), id = "TestCase4") {
                signature(data4, hex("6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"))
            }
            // output is truncated to 128 bits, which is not a valid HMAC signature
            encodableGroup(key(key5), id = "TestCase5") {
                signature(data5, hex("0e2aea68a90c8d37c988bcdb9fca6fa8"), ExpectedResult.Invalid)
            }
            encodableGroup(key(key6), id = "TestCase6") {
                signature(data6, hex("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"))
            }
            encodableGroup(key(key6), id = "TestCase7") {
                signature(data7, hex("3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"))
            }
        }

        group(HmacTestParameters(SHA256)) {
            encodableGroup(key(key1), id = "TestCase1") {
                signature(data1, hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
            }
            encodableGroup(key(key2), id = "TestCase2") {
                signature(data2, hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
            }
            encodableGroup(key(key3), id = "TestCase3") {
                signature(data3, hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"))
            }
            encodableGroup(key(key4), id = "TestCase4") {
                signature(data4, hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"))
            }
            // output is truncated to 128 bits, which is not a valid HMAC signature
            encodableGroup(key(key5), id = "TestCase5") {
                signature(data5, hex("a3b6167473100ee06e0c796c2955552b"), ExpectedResult.Invalid)
            }
            encodableGroup(key(key6), id = "TestCase6") {
                signature(data6, hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))
            }
            encodableGroup(key(key6), id = "TestCase7") {
                signature(data7, hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"))
            }
        }

        group(HmacTestParameters(SHA384)) {
            encodableGroup(key(key1), id = "TestCase1") {
                signature(data1, hex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"))
            }
            encodableGroup(key(key2), id = "TestCase2") {
                signature(data2, hex("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"))
            }
            encodableGroup(key(key3), id = "TestCase3") {
                signature(data3, hex("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"))
            }
            encodableGroup(key(key4), id = "TestCase4") {
                signature(data4, hex("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"))
            }
            // output is truncated to 128 bits, which is not a valid HMAC signature
            encodableGroup(key(key5), id = "TestCase5") {
                signature(data5, hex("3abf34c3503b2a23a46efc619baef897"), ExpectedResult.Invalid)
            }
            encodableGroup(key(key6), id = "TestCase6") {
                signature(data6, hex("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"))
            }
            encodableGroup(key(key6), id = "TestCase7") {
                signature(data7, hex("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"))
            }
        }

        group(HmacTestParameters(SHA512)) {
            encodableGroup(key(key1), id = "TestCase1") {
                signature(
                    data1,
                    hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
                )
            }
            encodableGroup(key(key2), id = "TestCase2") {
                signature(
                    data2,
                    hex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
                )
            }
            encodableGroup(key(key3), id = "TestCase3") {
                signature(
                    data3,
                    hex("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")
                )
            }
            encodableGroup(key(key4), id = "TestCase4") {
                signature(
                    data4,
                    hex("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")
                )
            }
            // output is truncated to 128 bits, which is not a valid HMAC signature
            encodableGroup(key(key5), id = "TestCase5") {
                signature(data5, hex("415fad6271580a531d4179bc891d87a6"), ExpectedResult.Invalid)
            }
            encodableGroup(key(key6), id = "TestCase6") {
                signature(
                    data6,
                    hex("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
                )
            }
            encodableGroup(key(key6), id = "TestCase7") {
                signature(
                    data7,
                    hex("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")
                )
            }
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        hmacDigests.forEach { digest ->
            group(HmacTestParameters(digest)) {
                generateEncodableGroups(algorithm.keyGenerator(digest), iterations = 2) { key ->
                    // generated keys have the size of the digest block
                    assertEquals(digest.digestBlockSize, key.encodeToByteString(HMAC.Key.Format.RAW).size, "Generated key size")
                    generateSignatures(
                        generator = key.signatureGenerator(),
                        messageSizes = listOf(0, 1, 15, 16, 17, 100, 1000, 10000) + List(2) { CryptographyRandom.nextInt(10000) },
                    )
                    otherKeySignature(algorithm.keyGenerator(digest).generateKey().signatureGenerator())
                }
                // large data is stored and validated by every provider, so it's generated only for a single key
                if (digest == SHA256) generateEncodableGroups(algorithm.keyGenerator(digest), iterations = 1) { key ->
                    generateSignatures(key.signatureGenerator(), messageSizes = listOf(1_000_000))
                }
            }
        }
    }

    // keys of arbitrary sizes are supported
    @Test
    fun keySizes() = test("key-sizes") { algorithm ->
        hmacDigests.forEach { digest ->
            group(HmacTestParameters(digest)) {
                listOf(1, digest.digestSize, digest.digestBlockSize, digest.digestBlockSize + 1, 1000).forEach { keySize ->
                    val key = algorithm.keyDecoder(digest).decodeFromByteString(HMAC.Key.Format.RAW, randomBytes(keySize))
                    encodableGroup(key, id = "$keySize") {
                        generateSignatures(key.signatureGenerator(), messageSizes = listOf(0, 100))
                    }
                }
            }
        }
    }
}

private val hmacDigests = listOf(SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512)
