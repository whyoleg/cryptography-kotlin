/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*
import kotlin.test.*

typealias RsaTestGroupValidator<Pub, Priv, V> = TestGroupValidator<RsaTestParameters, RsaKeyPairTestGroupValidator<Pub, Priv, V>>
typealias RsaKeyPairTestGroupValidator<Pub, Priv, V> = KeyPairTestGroupValidator<RSA.PublicKey.Format, Pub, RSA.PrivateKey.Format, Priv, V>

@Serializable
data class RsaTestParameters(
    val digest: SerializableDigest,
    val keySizeBits: Int,
) : TestParameters {
    val keySize: Int get() = keySizeBits.bits.inBytes
    override val id: String get() = "${digest.name}-$keySizeBits"
}

// RSA-* -> [digest, key size] -> [key pair] -> V (variant specific)
abstract class RsaAlgorithmTest<A : RSA<Pub, Priv, KP>, Pub : RSA.PublicKey, Priv : RSA.PrivateKey<Pub>, KP : RSA.KeyPair<Pub, Priv>, V : TestInputValidator>(
    provider: CryptographyProvider,
    algorithmId: CryptographyAlgorithmId<A>,
    algorithmLimitation: (TestLimitationScope.() -> TestLimitation?)?,
    // digest is used only for encoding (f.e. JWK), so there is no need to test all of them
    private val singleDigest: Boolean = false,
    suiteId: String = algorithmId.name,
) : AlgorithmTest<A, RsaTestGroupValidator<Pub, Priv, V>>(provider, algorithmId, algorithmLimitation, suiteId) {

    final override fun TestValidatorScope.validator(algorithm: A): RsaTestGroupValidator<Pub, Priv, V> = group<RsaTestParameters, _>(
        // all providers fail when creating decoders and generators
        limitation = { (digest) -> failsIfDigestUnsupported(digest) },
    ) { parameters ->
        keyPairs(algorithm.keyPairCodec(parameters)) { publicKeys, privateKeys ->
            keyValidator(parameters, publicKeys, privateKeys)
        }
    }

    // validator of the key pair group
    protected abstract fun TestValidatorScope.keyValidator(parameters: RsaTestParameters, publicKeys: List<Pub>, privateKeys: List<Priv>): V

    // generates random data for the generated key pair
    context(context: TestGenerationContext)
    protected abstract suspend fun V.generateRandom(parameters: RsaTestParameters, keyPair: KP)

    @Test
    fun random() = test("random") { algorithm ->
        val cases = when {
            singleDigest -> listOf(2048 to SHA256, 3072 to SHA256, 4096 to SHA256)
            else         -> listOf(2048 to SHA1, 2048 to SHA256, 2048 to SHA512, 2048 to SHA3_256, 3072 to SHA256, 4096 to SHA512)
        }
        cases.forEach { (keySizeBits, digest) ->
            val parameters = RsaTestParameters(digest, keySizeBits)
            group(parameters) {
                generateKeyPairGroups(
                    generator = algorithm.keyPairGenerator(keySizeBits.bits, digest),
                    iterations = 1,
                    publicKey = { it.publicKey },
                    privateKey = { it.privateKey },
                ) { keyPair ->
                    generateRandom(parameters, keyPair)
                }
            }
        }
    }
}

private fun <Pub : RSA.PublicKey, Priv : RSA.PrivateKey<Pub>> RSA<Pub, Priv, *>.keyPairCodec(
    parameters: RsaTestParameters,
): KeyPairTestCodec<RSA.PublicKey.Format, Pub, RSA.PrivateKey.Format, Priv> = keyPairCodec(
    publicKey = encodableCodec(publicKeyDecoder(parameters.digest)) {
        jwk(RSA.PublicKey.Format.JWK, "kty", "n", "e")
        // with the public exponent 65537
        der(RSA.PublicKey.Format.DER, RSA.PublicKey.Format.PEM, PemLabel.PublicKey, sizes = listOf(parameters.keySize + 38))
        der(RSA.PublicKey.Format.DER.PKCS1, RSA.PublicKey.Format.PEM.PKCS1, PemLabel.RsaPublicKey)
    },
    privateKey = encodableCodec(privateKeyDecoder(parameters.digest)) {
        jwk(RSA.PrivateKey.Format.JWK, "kty", "n", "e", "d", "p", "q", "dp", "dq", "qi")
        der(RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.PEM, PemLabel.PrivateKey)
        der(RSA.PrivateKey.Format.DER.PKCS1, RSA.PrivateKey.Format.PEM.PKCS1, PemLabel.RsaPrivateKey)
    },
    getPublicKey = { it.getPublicKey() },
)
