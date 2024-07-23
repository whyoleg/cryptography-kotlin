/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.math.*
import java.security.interfaces.*
import java.security.spec.*

internal sealed class JdkEc<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>>(
    protected val state: JdkCryptographyState,
) : EC<PublicK, PrivateK, KP> {
    private fun algorithmParameters(spec: AlgorithmParameterSpec): JAlgorithmParameters {
        return state.algorithmParameters("EC").also { it.init(spec) }
    }

    protected abstract fun JPublicKey.convert(): PublicK
    protected abstract fun JPrivateKey.convert(): PrivateK
    protected abstract fun JKeyPair.convert(): KP

    final override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, PublicK> {
        return EcPublicKeyDecoder(algorithmParameters(ECGenParameterSpec(curve.jdkName)).curveName())
    }

    final override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, PrivateK> {
        return EcPrivateKeyDecoder(algorithmParameters(ECGenParameterSpec(curve.jdkName)).curveName())
    }

    final override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<KP> {
        return EcKeyPairGenerator(ECGenParameterSpec(curve.jdkName))
    }

    private val EC.Curve.jdkName: String
        get() = when (this) {
            EC.Curve.P256 -> "secp256r1"
            EC.Curve.P384 -> "secp384r1"
            EC.Curve.P521 -> "secp521r1"
            else          -> name
        }

    private inner class EcKeyPairGenerator(
        private val keyGenParameters: ECGenParameterSpec,
    ) : JdkKeyPairGenerator<KP>(state, "EC") {
        override fun JKeyPairGenerator.init() {
            initialize(keyGenParameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): KP = with(this@JdkEc) { convert() }
    }

    private inner class EcPublicKeyDecoder(
        private val curveName: String,
    ) : JdkPublicKeyDecoder<EC.PublicKey.Format, PublicK>(state, "EC") {
        override fun JPublicKey.convert(): PublicK {
            check(this is ECPublicKey)

            val keyCurve = algorithmParameters(params).curveName()
            check(curveName == keyCurve) { "Key curve $keyCurve is not equal to expected curve $curveName" }

            return with(this@JdkEc) { convert() }
        }

        override fun decodeFromBlocking(format: EC.PublicKey.Format, input: ByteArray): PublicK = when (format) {
            EC.PublicKey.Format.JWK -> error("$format is not supported")
            EC.PublicKey.Format.RAW -> {
                check(input.isNotEmpty() && input[0].toInt() == 4) { "Encoded key should be in uncompressed format" }
                val parameters = algorithmParameters(ECGenParameterSpec(curveName)).getParameterSpec(ECParameterSpec::class.java)
                val fieldSize = parameters.curveOrderSize()
                check(input.size == fieldSize * 2 + 1) { "Wrong encoded key size" }

                val x = input.copyOfRange(1, fieldSize + 1)
                val y = input.copyOfRange(fieldSize + 1, fieldSize + 1 + fieldSize)
                val point = ECPoint(BigInteger(1, x), BigInteger(1, y))

                keyFactory.use {
                    it.generatePublic(ECPublicKeySpec(point, parameters))
                }.convert()
            }
            EC.PublicKey.Format.DER -> decodeFromDer(input)
            EC.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, input))
        }
    }

    private inner class EcPrivateKeyDecoder(
        private val curveName: String,
    ) : JdkPrivateKeyDecoder<EC.PrivateKey.Format, PrivateK>(state, "EC") {
        override fun JPrivateKey.convert(): PrivateK {
            check(this is ECPrivateKey)

            val keyCurve = algorithmParameters(params).curveName()
            check(curveName == keyCurve) { "Key curve $keyCurve is not equal to expected curve $curveName" }

            return with(this@JdkEc) { convert() }
        }

        override fun decodeFromBlocking(format: EC.PrivateKey.Format, input: ByteArray): PrivateK = when (format) {
            EC.PrivateKey.Format.JWK -> error("$format is not supported")
            EC.PrivateKey.Format.DER -> decodeFromDer(input)
            EC.PrivateKey.Format.PEM      -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, input))
            EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertSec1ToPkcs8(input))
            EC.PrivateKey.Format.PEM.SEC1 -> decodeFromDer(convertSec1ToPkcs8(unwrapPem(PemLabel.EcPrivateKey, input)))
        }

        private fun convertSec1ToPkcs8(input: ByteArray): ByteArray {
            val ecPrivateKey = DER.decodeFromByteArray(EcPrivateKey.serializer(), input)

            checkNotNull(ecPrivateKey.parameters) { "EC Parameters are not present in the key" }

            val privateKeyInfo = PrivateKeyInfo(
                version = 0,
                privateKeyAlgorithm = EcKeyAlgorithmIdentifier(ecPrivateKey.parameters),
                privateKey = input
            )
            return DER.encodeToByteArray(PrivateKeyInfo.serializer(), privateKeyInfo)
        }
    }

    protected abstract class BaseEcPublicKey(
        private val key: JPublicKey,
    ) : EC.PublicKey, JdkEncodableKey<EC.PublicKey.Format>(key) {
        final override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
            EC.PublicKey.Format.JWK -> error("$format is not supported")
            EC.PublicKey.Format.RAW -> {
                key as ECPublicKey

                val fieldSize = key.params.curveOrderSize()
                val x = key.w.affineX.toByteArray().trimLeadingZeros()
                val y = key.w.affineY.toByteArray().trimLeadingZeros()
                check(x.size <= fieldSize && y.size <= fieldSize)

                val output = ByteArray(fieldSize * 2 + 1)
                output[0] = 4 // uncompressed
                x.copyInto(output, fieldSize - x.size + 1)
                y.copyInto(output, fieldSize * 2 - y.size + 1)
                output
            }
            EC.PublicKey.Format.DER -> encodeToDer()
            EC.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    protected abstract class BaseEcPrivateKey(
        key: JPrivateKey,
    ) : EC.PrivateKey, JdkEncodableKey<EC.PrivateKey.Format>(key) {
        final override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
            EC.PrivateKey.Format.JWK      -> error("$format is not supported")
            EC.PrivateKey.Format.DER      -> encodeToDer()
            EC.PrivateKey.Format.PEM      -> wrapPem(PemLabel.PrivateKey, encodeToDer())
            EC.PrivateKey.Format.DER.SEC1 -> convertPkcs8ToSec1(encodeToDer())
            EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, convertPkcs8ToSec1(encodeToDer()))
        }

        private fun convertPkcs8ToSec1(input: ByteArray): ByteArray {
            val privateKeyInfo = DER.decodeFromByteArray(PrivateKeyInfo.serializer(), input)

            val privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm
            check(privateKeyAlgorithm is EcKeyAlgorithmIdentifier) {
                "Expected algorithm '${ObjectIdentifier.EC}', received: '${privateKeyAlgorithm.algorithm}'"
            }
            // the produced key could not contain parameters in underlying EcPrivateKey,
            // but they are available in `privateKeyAlgorithm`
            val ecPrivateKey = DER.decodeFromByteArray(EcPrivateKey.serializer(), privateKeyInfo.privateKey)
            if (ecPrivateKey.parameters != null) return privateKeyInfo.privateKey

            val enhancedEcPrivateKey = EcPrivateKey(
                version = ecPrivateKey.version,
                privateKey = ecPrivateKey.privateKey,
                parameters = privateKeyAlgorithm.parameters,
                publicKey = ecPrivateKey.publicKey
            )
            return DER.encodeToByteArray(EcPrivateKey.serializer(), enhancedEcPrivateKey)
        }
    }
}

internal fun ECParameterSpec.curveOrderSize(): Int {
    return (curve.field.fieldSize + 7) / 8
}

private fun JAlgorithmParameters.curveName(): String {
    return getParameterSpec(ECGenParameterSpec::class.java).name
}
