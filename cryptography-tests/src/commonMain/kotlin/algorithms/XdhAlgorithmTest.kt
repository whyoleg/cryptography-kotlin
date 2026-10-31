/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.serialization.*
import kotlin.test.*

typealias XdhTestGroupValidator = TestGroupValidator<XdhTestParameters, XdhKeyAgreementTestGroupValidator>
typealias XdhKeyAgreementTestGroupValidator = KeyAgreementTestGroupValidator<XDH.PublicKey.Format, XDH.PublicKey, XDH.PrivateKey.Format, XDH.PrivateKey, SharedSecretTestDataValidator>

@Serializable
data class XdhTestParameters(val curve: XDH.Curve) : TestParameters {
    override val id: String get() = curve.name
}

// XDH -> [curve] -> [two key pairs] -> [shared secret]
abstract class XdhAlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<XDH, XdhTestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = XDH,
    algorithmLimitation = {
        when {
            provider.isApple
                 -> fails("XDH is not supported")
            provider.isJdkDefault && platform.isJdk { major < 11 }
                -> fails("XDH is supported only since JDK 11 or with BouncyCastle")
            // https://bugs.openjdk.org/browse/JDK-8213363: produces wrong encodings, which can't be described by limitations
            provider.isJdkDefault && platform.isJdk { major < 12 }
                 -> skip("XDH is tested only since JDK 12")
            else -> null
        }
    },
) {
    override fun TestValidatorScope.validator(algorithm: XDH): XdhTestGroupValidator = group<XdhTestParameters, _>(
        limitation = { (curve) -> failsIfCurveUnsupported(curve) },
    ) { (curve) ->
        keyAgreements(algorithm.keyPairCodec(curve)) { first, second ->
            sharedSecrets(
                first = first,
                second = second,
                publicKeyGenerator = { it.sharedSecretGenerator() },
                privateKeyGenerator = { it.sharedSecretGenerator() },
                sharedSecretSize = curve.keySize,
            )
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc7748
    @Test
    fun rfc7748() = test("rfc7748") {
        fun publicKey(content: String): TestMaterial<XDH.PublicKey.Format> = material(XDH.PublicKey.Format.RAW, hex(content))
        fun privateKey(content: String): TestMaterial<XDH.PrivateKey.Format> = material(XDH.PrivateKey.Format.RAW, hex(content))

        group(XdhTestParameters(XDH.Curve.X25519)) {
            // Section 5.2: scalar multiplication
            keyAgreementGroup(
                id = "5.2-1",
                first = keyPair(null, privateKey("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")),
                second = keyPair(publicKey("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"), null),
            ) {
                sharedSecret(hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))
            }
            keyAgreementGroup(
                id = "5.2-2",
                first = keyPair(null, privateKey("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")),
                second = keyPair(publicKey("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"), null),
            ) {
                sharedSecret(hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"))
            }
            // Section 6.1: Diffie-Hellman
            keyAgreementGroup(
                id = "6.1",
                first = keyPair(
                    publicKey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
                    privateKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
                ),
                second = keyPair(
                    publicKey("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
                    privateKey("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
                ),
            ) {
                sharedSecret(hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
            }
        }
        group(XdhTestParameters(XDH.Curve.X448)) {
            // Section 5.2: scalar multiplication
            keyAgreementGroup(
                id = "5.2-1",
                first = keyPair(
                    null,
                    privateKey("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
                ),
                second = keyPair(
                    publicKey("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"),
                    null
                ),
            ) {
                sharedSecret(hex("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"))
            }
            keyAgreementGroup(
                id = "5.2-2",
                first = keyPair(
                    null,
                    privateKey("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
                ),
                second = keyPair(
                    publicKey("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"),
                    null
                ),
            ) {
                sharedSecret(hex("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"))
            }
            // Section 6.2: Diffie-Hellman
            keyAgreementGroup(
                id = "6.2",
                first = keyPair(
                    publicKey("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"),
                    privateKey("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"),
                ),
                second = keyPair(
                    publicKey("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"),
                    privateKey("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"),
                ),
            ) {
                sharedSecret(hex("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"))
            }
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        XDH.Curve.entries.forEach { curve ->
            group(XdhTestParameters(curve)) {
                generateKeyAgreementGroups(
                    generator = algorithm.keyPairGenerator(curve),
                    iterations = 3,
                    publicKey = XDH.KeyPair::publicKey,
                    privateKey = XDH.KeyPair::privateKey,
                ) { first, second ->
                    generateSharedSecret(first.privateKey.sharedSecretGenerator(), second.publicKey)
                }
            }
        }
    }
}

// size of keys and shared secret in bytes
private val XDH.Curve.keySize: Int
    get() = when (this) {
        XDH.Curve.X25519 -> 32
        XDH.Curve.X448   -> 56
    }

private fun XDH.keyPairCodec(
    curve: XDH.Curve,
): KeyPairTestCodec<XDH.PublicKey.Format, XDH.PublicKey, XDH.PrivateKey.Format, XDH.PrivateKey> = keyPairCodec(
    publicKey = encodableCodec(
        decoder = publicKeyDecoder(curve),
        limitation = { failsIfCurveUnsupportedInBrowser(curve) },
    ) {
        jwk(XDH.PublicKey.Format.JWK, "kty", "crv", "x")
        raw(XDH.PublicKey.Format.RAW, size = curve.keySize)
        der(XDH.PublicKey.Format.DER, XDH.PublicKey.Format.PEM, PemLabel.PublicKey)
    },
    privateKey = encodableCodec(
        decoder = privateKeyDecoder(curve),
        limitation = { operation ->
            failsIfCurveUnsupportedInBrowser(curve) ?: when (operation) {
                is EncodableTestOperation.DecodeFromByteString if operation.containsPublicKey &&
                        operation.material.format != XDH.PrivateKey.Format.JWK && (
                        (provider.isWebCrypto && platform.isBrowser) ||
                                provider.isOpenssl3 { version.startsWith("3.0") } ||
                                (provider.isJdk && platform.isAndroid))
                    -> fails("Decoding private key with `publicKey` field is not supported")
                // JWK contains the public key
                is EncodableTestOperation.EncodeToByteString if operation.format == XDH.PrivateKey.Format.JWK
                    -> failsIfPublicKeyIsNotDerivable(operation.source)
                else -> null
            }
        },
    ) {
        jwk(XDH.PrivateKey.Format.JWK, "kty", "crv", "x", "d", containsPublicKey = true)
        raw(XDH.PrivateKey.Format.RAW, size = curve.keySize)
        der(
            XDH.PrivateKey.Format.DER, XDH.PrivateKey.Format.PEM, PemLabel.PrivateKey,
            containsPublicKey = ::hasPrivateKeyInfoPublicKey,
            check = ::assertPrivateKeyInfoEquals,
        )
    },
    getPublicKey = { it.getPublicKey() },
    limitation = { operation ->
        failsIfCurveUnsupportedInBrowser(curve) ?: when (operation) {
            is KeyPairTestOperation.GetPublicKey -> failsIfPublicKeyIsNotDerivable(operation.source)
            else                                 -> null
        }
    },
)

// X448 is not supported by some providers, which fail at different stages:
// CryptoKit and Android fail when creating decoders and generators
private fun TestLimitationScope.failsIfCurveUnsupported(curve: XDH.Curve): TestLimitation? = when (curve) {
    XDH.Curve.X448 if provider.isCryptoKit                        -> fails("X448 is not supported")
    XDH.Curve.X448 if provider.isJdkDefault && platform.isAndroid -> fails("X448 is not supported on Android without BouncyCastle")
    else                                                          -> null
}

// browsers fail only when decoding or generating keys
private fun TestLimitationScope.failsIfCurveUnsupportedInBrowser(curve: XDH.Curve): TestLimitation? = when (curve) {
    XDH.Curve.X448 if provider.isWebCrypto && platform.isBrowser -> fails("X448 is not supported in browsers")
    else                                                         -> null
}
