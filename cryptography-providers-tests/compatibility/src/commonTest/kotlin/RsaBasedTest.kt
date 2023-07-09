/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
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
        val digest: String,
        val digestSizeBytes: Int,
    ) : TestParameters

    protected suspend fun CompatibilityTestContext<A>.generateKeys(
        block: suspend (keyPair: KP, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        generateRsaKeySizes { keySize ->
            generateDigests { digest, digestSize ->
                val keyParameters = KeyParameters(keySize.inBits, digest.name, digestSize)
                val keyParametersId = api.keyPairs.saveParameters(keyParameters)
                algorithm.keyPairGenerator(keySize, digest).generateKeys(keyIterations) { keyPair ->
                    val keyReference = api.keyPairs.saveData(
                        keyParametersId, KeyPairData(
                            public = KeyData(keyPair.publicKey.encodeTo(RSA.PublicKey.Format.values(), ::supportsKeyFormat)),
                            private = KeyData(keyPair.privateKey.encodeTo(RSA.PrivateKey.Format.values(), ::supportsKeyFormat))
                        )
                    )
                    block(keyPair, keyReference, keyParameters)
                }
            }
        }
    }

    protected suspend fun CompatibilityTestContext<A>.validateKeys() = buildMap {
        api.keyPairs.getParameters<KeyParameters> { (_, digestName), parametersId ->
            val digest = digest(digestName)

            val privateKeyDecoder = algorithm.privateKeyDecoder(digest)
            val publicKeyDecoder = algorithm.publicKeyDecoder(digest)

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference ->
                val publicKeys = publicKeyDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = RSA.PublicKey.Format::valueOf,
                    supports = ::supportsKeyFormat
                ) { key, format, bytes ->
                    when (format) {
                        RSA.PublicKey.Format.DER, RSA.PublicKey.Format.PEM ->
                            assertContentEquals(bytes, key.encodeTo(format), "Public Key $format encoding")
                        RSA.PublicKey.Format.JWK                           -> {}
                    }
                }
                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = RSA.PrivateKey.Format::valueOf,
                    supports = ::supportsKeyFormat
                ) { key, format, bytes ->
                    when (format) {
                        RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.PEM -> {
                            assertContentEquals(bytes, key.encodeTo(format), "Private Key $format encoding")
                        }
                        RSA.PrivateKey.Format.JWK                            -> {}
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
