/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*
import kotlin.test.*

typealias EcdsaTestGroupValidator = EcTestGroupValidator<
        EcKeyPairTestGroupValidator<ECDSA.PublicKey, ECDSA.PrivateKey, TestGroupValidator<EcdsaSignatureTestParameters, SignatureTestDataValidator>>
        >

@Serializable
data class EcdsaSignatureTestParameters(
    val digest: SerializableDigest?,
    val format: ECDSA.SignatureFormat,
) : TestParameters {
    override val id: String get() = "${digest?.name ?: "NONE"}-${format.name}"
}

// ECDSA -> [curve] -> [key pair] -> [digest, signature format] -> [signature]
abstract class EcdsaAlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<ECDSA, EcdsaTestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = ECDSA,
) {
    override fun TestValidatorScope.validator(algorithm: ECDSA): EcdsaTestGroupValidator = ecCurves(algorithm) { curve, keys ->
        keyPairs(keys) { publicKeys, privateKeys ->
            group<EcdsaSignatureTestParameters, _>(
                limitation = { (digest) ->
                    when (digest) {
                        null if (provider.isWebCrypto || provider.isCryptoKit)
                            -> fails("ECDSA without digest is not supported")
                        // all providers fail when creating signers and verifiers
                        else -> failsIfSignatureDigestUnsupported(digest)
                    }
                },
            ) { (digest, format) ->
                signatures(
                    verifiers = publicKeys.map { it.signatureVerifier(digest, format) },
                    generators = privateKeys.map { it.signatureGenerator(digest, format) },
                    signatureSizes = when (format) {
                        ECDSA.SignatureFormat.RAW -> listOf(2 * curve.orderSize)
                        // SEQUENCE of two INTEGERs, each could have leading zero or be shorter
                        ECDSA.SignatureFormat.DER -> 8..(2 * curve.orderSize + 9)
                    },
                    deterministic = false,
                    limitation = { operation ->
                        when (digest) {
                            // `NONEwithECDSA` supports only messages up to 64 bytes
                            null if operation.messageSize > 64 && provider.isJdkDefault
                                -> fails("ECDSA without digest supports only messages up to 64 bytes")
                            else -> null
                        }
                    },
                )
            }
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        ecTestCurves.forEach { curve ->
            group(EcTestParameters(curve)) {
                generateKeyPairGroups(
                    generator = algorithm.keyPairGenerator(curve),
                    iterations = 2,
                    publicKey = ECDSA.KeyPair::publicKey,
                    privateKey = ECDSA.KeyPair::privateKey,
                ) { keyPair ->
                    ecdsaDigests.forEach { digest ->
                        ECDSA.SignatureFormat.entries.forEach { format ->
                            group(EcdsaSignatureTestParameters(digest, format)) {
                                generateSignatures(
                                    generator = keyPair.privateKey.signatureGenerator(digest, format),
                                    // without digest, the message is used as a hash, so empty message and message with a single zero byte are equal
                                    messageSizes = when (digest) {
                                        null -> listOf(1, 100, 10000) + List(1) { 1 + CryptographyRandom.nextInt(10000) }
                                        else -> listOf(0, 1, 100, 10000) + List(1) { CryptographyRandom.nextInt(10000) }
                                    },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // point which is not on the curve
    @Test
    fun invalidPublicKey() = test("invalid-public-key") { algorithm ->
        ecTestCurves.forEach { curve ->
            group(EcTestParameters(curve)) {
                val keyPair = codec.generate(algorithm.keyPairGenerator(curve))
                val publicKey = keyPair.publicKey.encodeToByteString(EC.PublicKey.Format.RAW)
                keyPairGroup(
                    publicKey = material(EC.PublicKey.Format.RAW, publicKey.flipBit(publicKey.size - 1), ExpectedResult.Invalid),
                    privateKey = null,
                )
            }
        }
    }
}

private val ecdsaDigests = listOf(null, SHA256, SHA512, SHA3_256)
