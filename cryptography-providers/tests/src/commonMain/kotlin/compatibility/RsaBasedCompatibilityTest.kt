/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.serialization.*
import kotlin.test.*

private val publicKeyFormats = listOf(
    RSA.PublicKey.Format.JWK,
    RSA.PublicKey.Format.DER,
    RSA.PublicKey.Format.PEM,
    RSA.PublicKey.Format.DER.PKCS1,
    RSA.PublicKey.Format.PEM.PKCS1,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    RSA.PrivateKey.Format.JWK,
    RSA.PrivateKey.Format.DER,
    RSA.PrivateKey.Format.PEM,
    RSA.PrivateKey.Format.DER.PKCS1,
    RSA.PrivateKey.Format.PEM.PKCS1,
).associateBy { it.name }

abstract class RsaBasedCompatibilityTest<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>, A : RSA<PublicK, PrivateK, KP>>(
    algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : CompatibilityTest<A>(algorithmId, provider) {

    @Serializable
    protected data class KeyParameters(
        val keySizeBits: Int,
        val digestName: String,
        val digestSizeBytes: Int,
    ) : TestParameters {
        val digest get() = digest(digestName)
    }

    protected suspend fun CompatibilityTestScope<A>.generateKeys(
        isStressTest: Boolean,
        // hack for RSA RAW and RSA PKCS1 encryption
        singleDigest: CryptographyAlgorithmId<Digest>? = null,
        block: suspend (keyPair: KP, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        singleDigest?.let {
            require(supportsDigest(it)) { "Unsupported digest: $it" }
        }
        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }
        generateRsaKeySizes { keySize ->
            generateDigestsForCompatibility { digest, digestSize ->
                // hack for RSA RAW and RSA PKCS1 encryption:
                // there is no need to run for every digest as it's not used
                if (singleDigest != null && singleDigest != digest) return@generateDigestsForCompatibility
                if (!supportsDigest(digest)) return@generateDigestsForCompatibility

                val keyParameters = KeyParameters(keySize.inBits, digest.name, digestSize)
                val keyParametersId = api.keyPairs.saveParameters(keyParameters)
                algorithm.keyPairGenerator(keySize, digest).generateKeys(keyIterations) { keyPair ->
                    val keyReference = api.keyPairs.saveData(
                        keyParametersId, KeyPairData(
                            public = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat)),
                            private = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))
                        )
                    )
                    block(keyPair, keyReference, keyParameters)
                }
            }
        }
    }

    protected suspend fun CompatibilityTestScope<A>.validateKeys() = buildMap {
        api.keyPairs.getParameters<KeyParameters> { parameters, parametersId, _ ->
            if (!supportsDigest(parameters.digest)) return@getParameters

            val privateKeyDecoder = algorithm.privateKeyDecoder(parameters.digest)
            val publicKeyDecoder = algorithm.publicKeyDecoder(parameters.digest)

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                val publicKeys = publicKeyDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = publicKeyFormats::getValue,
                    supports = ::supportsKeyFormat
                ) { key, format, bytes ->
                    when (format) {
                        RSA.PublicKey.Format.DER, RSA.PublicKey.Format.DER.PKCS1 -> {
                            assertContentEquals(bytes, key.encodeToByteString(format), "Public Key $format encoding")
                        }
                        RSA.PublicKey.Format.PEM, RSA.PublicKey.Format.PEM.PKCS1 -> {
                            val expected = PemDocument.decode(bytes)
                            val actual = PemDocument.decode(key.encodeToByteString(format))

                            val expectedLabel = when (format) {
                                RSA.PublicKey.Format.PEM       -> PemLabel.PublicKey
                                RSA.PublicKey.Format.PEM.PKCS1 -> PemLabel.RsaPublicKey
                                else                           -> {}
                            }

                            assertEquals(expected.label, actual.label)
                            assertEquals(expectedLabel, actual.label)

                            assertContentEquals(expected.content, actual.content, "Public Key $format content encoding")
                        }
                        RSA.PublicKey.Format.JWK                                 -> {}

                    }
                }
                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = privateKeyFormats::getValue,
                    supports = ::supportsKeyFormat
                ) { key, format, bytes ->
                    when (format) {
                        RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.DER.PKCS1 -> {
                            assertContentEquals(bytes, key.encodeToByteString(format), "Private Key $format encoding")
                        }
                        RSA.PrivateKey.Format.PEM, RSA.PrivateKey.Format.PEM.PKCS1 -> {
                            val expected = PemDocument.decode(bytes)
                            val actual = PemDocument.decode(key.encodeToByteString(format))

                            val expectedLabel = when (format) {
                                RSA.PrivateKey.Format.PEM       -> PemLabel.PrivateKey
                                RSA.PrivateKey.Format.PEM.PKCS1 -> PemLabel.RsaPrivateKey
                                else                            -> {}
                            }

                            assertEquals(expected.label, actual.label)
                            assertEquals(expectedLabel, actual.label)

                            assertContentEquals(expected.content, actual.content, "Private Key $format content encoding")
                        }

                        RSA.PrivateKey.Format.JWK                                  -> {}
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
