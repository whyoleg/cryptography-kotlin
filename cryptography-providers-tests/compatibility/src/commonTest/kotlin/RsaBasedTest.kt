/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.providers.tests.support.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 3

abstract class RsaBasedTest<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>, A : RSA<PublicK, PrivateK, KP>>(
    algorithmId: CryptographyAlgorithmId<A>,
) : CompatibilityTest<A>(algorithmId) {

    @Serializable
    protected data class KeyParameters(
        val keySizeBits: Int,
        val digestName: String,
        val digestSizeBytes: Int,
    ) : TestParameters {
        val digest get() = digest(digestName)
    }

    protected suspend fun CompatibilityTestScope<A>.generateKeys(
        block: suspend (keyPair: KP, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        generateRsaKeySizes { keySize ->
            generateDigestsForCompatibility { digest, digestSize ->
                if (!supportsDigest(digest)) return@generateDigestsForCompatibility

                val keyParameters = KeyParameters(keySize.inBits, digest.name, digestSize)
                val keyParametersId = api.keyPairs.saveParameters(keyParameters)
                algorithm.keyPairGenerator(keySize, digest).generateKeys(keyIterations) { keyPair ->
                    val keyReference = api.keyPairs.saveData(
                        keyParametersId, KeyPairData(
                            public = KeyData(keyPair.publicKey.encodeTo(RSA.PublicKey.Format.entries, ::supportsKeyFormat)),
                            private = KeyData(keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.entries, ::supportsKeyFormat))
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
                    formatOf = RSA.PublicKey.Format::valueOf,
                    supports = ::supportsKeyFormat
                ) { key, format, bytes ->
                    when (format) {
                        RSA.PublicKey.Format.DER,
                        RSA.PublicKey.Format.PEM,
                        RSA.PublicKey.Format.DER_RSA,
                        RSA.PublicKey.Format.PEM_RSA,
                                                 ->
                            assertContentEquals(bytes, key.encodeTo(format), "Public Key $format encoding")
                        RSA.PublicKey.Format.JWK -> {}

                    }
                }
                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = RSA.PrivateKey.Format::valueOf,
                    supports = ::supportsKeyFormat
                ) { key, format, bytes ->
                    when (format) {
                        RSA.PrivateKey.Format.DER,
                        RSA.PrivateKey.Format.PEM,
                        RSA.PrivateKey.Format.DER_RSA,
                        RSA.PrivateKey.Format.PEM_RSA,
                                                  ->
                            assertContentEquals(bytes, key.encodeTo(format), "Private Key $format encoding")
                        RSA.PrivateKey.Format.JWK -> {}
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
