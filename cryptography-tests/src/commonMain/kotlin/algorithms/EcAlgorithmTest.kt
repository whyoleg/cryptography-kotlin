/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.test.*

typealias EcTestGroupValidator<V> = TestGroupValidator<EcTestParameters, V>
typealias EcKeyPairTestCodec<Pub, Priv> = KeyPairTestCodec<EC.PublicKey.Format, Pub, EC.PrivateKey.Format, Priv>
typealias EcKeyPairTestGroupValidator<Pub, Priv, V> = KeyPairTestGroupValidator<EC.PublicKey.Format, Pub, EC.PrivateKey.Format, Priv, V>
typealias EcKeyAgreementTestGroupValidator<Pub, Priv, V> = KeyAgreementTestGroupValidator<EC.PublicKey.Format, Pub, EC.PrivateKey.Format, Priv, V>

@Serializable
data class EcTestParameters(val curve: SerializableEcCurve) : TestParameters {
    override val id: String get() = curve.name
}

typealias SerializableEcCurve = @Serializable(EcCurveSerializer::class) EC.Curve

// curves tested by ECDSA and ECDH
val ecTestCurves: List<EC.Curve> = listOf(
    EC.Curve.P256, EC.Curve.P384, EC.Curve.P521,
    EC.Curve.secp256k1,
    EC.Curve.brainpoolP256r1, EC.Curve.brainpoolP384r1, EC.Curve.brainpoolP512r1,
)

// shared parts of ECDSA and ECDH validators: [curve] -> V, `keys` decode, encode and generate keys of the curve
fun <Pub : EC.PublicKey, Priv : EC.PrivateKey<Pub>, V : TestInputValidator> TestValidatorScope.ecCurves(
    algorithm: EC<Pub, Priv, *>,
    validator: TestValidatorScope.(curve: EC.Curve, keys: EcKeyPairTestCodec<Pub, Priv>) -> V,
): EcTestGroupValidator<V> = group<EcTestParameters, V>(
    // all providers fail when creating decoders and generators
    limitation = { (curve) -> failsIfCurveUnsupported(curve) },
) { (curve) ->
    validator(curve, algorithm.keyPairCodec(curve))
}

// size of the curve order (and field) in bytes
val EC.Curve.orderSize: Int
    get() = when (this) {
        EC.Curve.P256, EC.Curve.secp256k1, EC.Curve.brainpoolP256r1 -> 32
        EC.Curve.P384, EC.Curve.brainpoolP384r1                     -> 48
        EC.Curve.P521                                               -> 66
        EC.Curve.brainpoolP512r1                                    -> 64
        else                                                        -> error("Unknown curve: $name")
    }

internal object EcCurveSerializer : KSerializer<EC.Curve> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("dev.whyoleg.cryptography.algorithms.EC.Curve", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: EC.Curve) {
        encoder.encodeString(value.name)
    }

    override fun deserialize(decoder: Decoder): EC.Curve = EC.Curve(decoder.decodeString())
}

// size of the public key in DER (SubjectPublicKeyInfo) format, depends on the size of the curve OID
private val EC.Curve.publicKeyDerSize: Int
    get() = when (this) {
        EC.Curve.P256            -> 91
        EC.Curve.P384            -> 120
        EC.Curve.P521            -> 158
        EC.Curve.secp256k1       -> 88
        EC.Curve.brainpoolP256r1 -> 92
        EC.Curve.brainpoolP384r1 -> 124
        EC.Curve.brainpoolP512r1 -> 158
        else                     -> error("Unknown curve: $name")
    }

private fun <Pub : EC.PublicKey, Priv : EC.PrivateKey<Pub>> EC<Pub, Priv, *>.keyPairCodec(
    curve: EC.Curve,
): EcKeyPairTestCodec<Pub, Priv> = keyPairCodec(
    publicKey = encodableCodec(
        decoder = publicKeyDecoder(curve),
        limitation = { operation ->
            when (operation) {
                is EncodableTestOperation.DecodeFromByteString if operation.material.expected == ExpectedResult.Invalid && provider.isJdkDefault
                     -> lenient("Public key point is not validated to be on the curve")
                is EncodableTestOperation.DecodeFromByteString if operation.material.format == EC.PublicKey.Format.RAW.Compressed
                     -> failsIfCompressedFormatUnsupported()
                is EncodableTestOperation.EncodeToByteString if operation.format == EC.PublicKey.Format.RAW.Compressed
                     -> failsIfCompressedFormatUnsupported()
                else -> null
            }
        },
    ) {
        jwk(EC.PublicKey.Format.JWK, "kty", "crv", "x", "y")
        raw(EC.PublicKey.Format.RAW, size = 1 + 2 * curve.orderSize)
        raw(EC.PublicKey.Format.RAW.Compressed, size = 1 + curve.orderSize)
        der(EC.PublicKey.Format.DER, EC.PublicKey.Format.PEM, PemLabel.PublicKey, sizes = listOf(curve.publicKeyDerSize))
    },
    privateKey = encodableCodec(
        decoder = privateKeyDecoder(curve),
        limitation = { operation ->
            when (operation) {
                is EncodableTestOperation.DecodeFromByteString if operation.material.format == EC.PrivateKey.Format.RAW && provider.isApple
                     -> fails("Decoding private key from RAW format is not supported")
                is EncodableTestOperation.DecodeFromByteString if !operation.containsPublicKey &&
                        (provider.isApple || (provider.isWebCrypto && platform.isBrowserSafari))
                     -> fails("Decoding private key without `publicKey` field is not supported")
                // JWK contains the public key
                is EncodableTestOperation.EncodeToByteString if operation.format == EC.PrivateKey.Format.JWK
                     -> failsIfPublicKeyIsNotDerivable(operation.source)
                else -> null
            }
        },
    ) {
        jwk(EC.PrivateKey.Format.JWK, "kty", "crv", "x", "y", "d", containsPublicKey = true)
        raw(EC.PrivateKey.Format.RAW, size = curve.orderSize)
        der(
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.PEM, PemLabel.PrivateKey,
            containsPublicKey = ::hasEcPrivateKeyInfoPublicKey,
            check = ::assertEcPrivateKeyInfoEquals,
        )
        der(
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1, PemLabel.EcPrivateKey,
            containsPublicKey = ::hasEcPrivateKeyPublicKey,
        ) { expected, actual ->
            assertEcPrivateKeyEquals(expected, actual, requireParameters = true)
        }
    },
    getPublicKey = { it.getPublicKey() },
    limitation = { operation ->
        when (operation) {
            is KeyPairTestOperation.GetPublicKey -> failsIfPublicKeyIsNotDerivable(operation.source)
            else                                 -> null
        }
    },
)

// the optional `publicKey` field of SEC1 `ECPrivateKey`, also when it's wrapped into `PrivateKeyInfo`
private fun hasEcPrivateKeyPublicKey(der: ByteString): Boolean =
    Der.decodeFromByteArray(EcPrivateKey.serializer(), der.toByteArray()).publicKey != null

private fun hasEcPrivateKeyInfoPublicKey(der: ByteString): Boolean =
    hasEcPrivateKeyPublicKey(ByteString(Der.decodeFromByteArray(PrivateKeyInfo.serializer(), der.toByteArray()).privateKey))

private fun assertEcPrivateKeyEquals(expected: ByteString, actual: ByteString, requireParameters: Boolean) {
    val expectedKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), expected.toByteArray())
    val actualKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), actual.toByteArray())

    assertEquals(expectedKey.version, actualKey.version, "EcPrivateKey.version")
    assertBytesEquals(ByteString(expectedKey.privateKey), ByteString(actualKey.privateKey)) { "EcPrivateKey.privateKey" }
    // different providers could encode or not encode parameters inside PrivateKeyInfo
    if (requireParameters || (expectedKey.parameters != null && actualKey.parameters != null)) {
        assertEquals(expectedKey.parameters, actualKey.parameters, "EcPrivateKey.parameters")
    }
    // public key is optional
    val expectedPublicKey = expectedKey.publicKey
    val actualPublicKey = actualKey.publicKey
    if (expectedPublicKey != null && actualPublicKey != null) {
        assertEquals(expectedPublicKey.unusedBits, actualPublicKey.unusedBits, "EcPrivateKey.publicKey.unusedBits")
        assertBytesEquals(ByteString(expectedPublicKey.byteArray), ByteString(actualPublicKey.byteArray)) { "EcPrivateKey.publicKey" }
    }
}

private fun assertEcPrivateKeyInfoEquals(expected: ByteString, actual: ByteString) {
    val expectedInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), expected.toByteArray())
    val actualInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), actual.toByteArray())

    assertEquals(expectedInfo.version, actualInfo.version, "PrivateKeyInfo.version")
    val expectedAlgorithm = assertIs<EcAlgorithmIdentifier>(expectedInfo.privateKeyAlgorithm)
    val actualAlgorithm = assertIs<EcAlgorithmIdentifier>(actualInfo.privateKeyAlgorithm)
    assertEquals(expectedAlgorithm.parameters, actualAlgorithm.parameters, "PrivateKeyInfo.privateKeyAlgorithm.parameters")
    assertEcPrivateKeyEquals(ByteString(expectedInfo.privateKey), ByteString(actualInfo.privateKey), requireParameters = false)
}

private val brainpoolCurves = setOf(EC.Curve.brainpoolP256r1, EC.Curve.brainpoolP384r1, EC.Curve.brainpoolP512r1)
private val nonNistCurves = brainpoolCurves + EC.Curve.secp256k1

private fun TestLimitationScope.failsIfCurveUnsupported(curve: EC.Curve): TestLimitation? = when (curve) {
    in nonNistCurves if (provider.isWebCrypto || provider.isApple || provider.isCryptoKit || (provider.isJdkDefault && platform.isAndroid))
        -> fails("secp256k1 and Brainpool curves are not supported")
    // removed with native SunEC implementation in https://bugs.openjdk.org/browse/JDK-8251547
    in nonNistCurves if provider.isJdkDefault && platform.isJdk { major >= 16 }
        -> fails("secp256k1 and Brainpool curves are not supported since JDK 16")
    in brainpoolCurves if provider.isJdkDefault && platform.isJdk { major < 11 }
        -> fails("Brainpool curves are supported only since JDK 11")
    else -> null
}

private fun TestLimitationScope.failsIfCompressedFormatUnsupported(): TestLimitation? = when {
    provider.isApple || (provider.isWebCrypto && platform.isBrowserSafari) -> fails("Compressed public key format is not supported")
    else                                                                   -> null
}
