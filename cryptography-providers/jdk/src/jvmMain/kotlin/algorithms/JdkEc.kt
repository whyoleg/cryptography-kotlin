/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
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

        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): PublicK = when (format) {
            EC.PublicKey.Format.JWK            -> error("$format is not supported")
            EC.PublicKey.Format.RAW            -> decodeFromRaw(bytes)
            EC.PublicKey.Format.RAW.Compressed -> decodeFromRaw(bytes)
            EC.PublicKey.Format.DER            -> decodeFromDer(bytes)
            EC.PublicKey.Format.PEM            -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }

        private fun decodeFromRaw(bytes: ByteArray): PublicK = run {
            check(bytes.isNotEmpty()) { "Encoded key is empty!" }
            val parameters = algorithmParameters(ECGenParameterSpec(curveName)).getParameterSpec(ECParameterSpec::class.java)
            val point = parameters.decodePoint(bytes)

            keyFactory.use {
                it.generatePublic(ECPublicKeySpec(point, parameters))
            }.convert()
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

        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): PrivateK = when (format) {
            EC.PrivateKey.Format.JWK      -> error("$format is not supported")
            EC.PrivateKey.Format.RAW      -> {
                val parameters = algorithmParameters(ECGenParameterSpec(curveName)).getParameterSpec(ECParameterSpec::class.java)
                // decode as positive value
                decode(ECPrivateKeySpec(BigInteger(1, bytes), parameters))
            }
            EC.PrivateKey.Format.DER      -> decodeFromDer(bytes)
            EC.PrivateKey.Format.PEM      -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
            EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertSec1ToPkcs8(bytes))
            EC.PrivateKey.Format.PEM.SEC1 -> decodeFromDer(convertSec1ToPkcs8(unwrapPem(PemLabel.EcPrivateKey, bytes)))
        }

        private fun convertSec1ToPkcs8(input: ByteArray): ByteArray {
            val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), input)

            checkNotNull(ecPrivateKey.parameters) { "EC Parameters are not present in the key" }

            val privateKeyInfo = PrivateKeyInfo(
                version = 0,
                privateKeyAlgorithm = EcKeyAlgorithmIdentifier(ecPrivateKey.parameters),
                privateKey = input
            )
            return Der.encodeToByteArray(PrivateKeyInfo.serializer(), privateKeyInfo)
        }
    }

    protected abstract class BaseEcPublicKey(
        private val key: JPublicKey,
    ) : EC.PublicKey, JdkEncodableKey<EC.PublicKey.Format>(key) {
        final override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
            EC.PublicKey.Format.JWK            -> error("$format is not supported")
            EC.PublicKey.Format.RAW            -> encodeToRaw(compressed = false)
            EC.PublicKey.Format.RAW.Compressed -> encodeToRaw(compressed = true)
            EC.PublicKey.Format.DER            -> encodeToDer()
            EC.PublicKey.Format.PEM            -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }

        private fun encodeToRaw(compressed: Boolean): ByteArray = run {
            key as ECPublicKey

            val fieldSize = key.params.curveOrderSize()
            val x = key.w.affineX.toByteArray().trimLeadingZeros()
            val y = key.w.affineY.toByteArray().trimLeadingZeros()
            check(x.size <= fieldSize && y.size <= fieldSize)

            if (compressed) {
                val output = ByteArray(fieldSize + 1)
                output[0] = if (!BigInteger(1, y).testBit(0)) 0x02 else 0x03
                x.copyInto(output, fieldSize - x.size + 1)
                output
            } else {
                val output = ByteArray(fieldSize * 2 + 1)
                output[0] = 0x04
                x.copyInto(output, fieldSize - x.size + 1)
                y.copyInto(output, fieldSize * 2 - y.size + 1)
                output
            }
        }

    }

    protected abstract class BaseEcPrivateKey(
        private val key: JPrivateKey,
    ) : EC.PrivateKey, JdkEncodableKey<EC.PrivateKey.Format>(key) {
        final override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
            EC.PrivateKey.Format.JWK      -> error("$format is not supported")
            EC.PrivateKey.Format.DER      -> encodeToDer()
            EC.PrivateKey.Format.RAW      -> {
                key as ECPrivateKey
                val fieldSize = key.params.curveOrderSize()
                val secret = key.s.toByteArray().trimLeadingZeros()
                secret.copyInto(ByteArray(fieldSize), fieldSize - secret.size)
            }
            EC.PrivateKey.Format.PEM      -> wrapPem(PemLabel.PrivateKey, encodeToDer())
            EC.PrivateKey.Format.DER.SEC1 -> convertPkcs8ToSec1(encodeToDer())
            EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, convertPkcs8ToSec1(encodeToDer()))
        }

        private fun convertPkcs8ToSec1(input: ByteArray): ByteArray {
            val privateKeyInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)

            val privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm
            check(privateKeyAlgorithm is EcKeyAlgorithmIdentifier) {
                "Expected algorithm '${ObjectIdentifier.EC}', received: '${privateKeyAlgorithm.algorithm}'"
            }
            // the produced key could not contain parameters in underlying EcPrivateKey,
            // but they are available in `privateKeyAlgorithm`
            val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), privateKeyInfo.privateKey)
            if (ecPrivateKey.parameters != null) return privateKeyInfo.privateKey

            val enhancedEcPrivateKey = EcPrivateKey(
                version = ecPrivateKey.version,
                privateKey = ecPrivateKey.privateKey,
                parameters = privateKeyAlgorithm.parameters,
                publicKey = ecPrivateKey.publicKey
            )
            return Der.encodeToByteArray(EcPrivateKey.serializer(), enhancedEcPrivateKey)
        }
    }
}

internal fun ECParameterSpec.curveOrderSize(): Int {
    return (curve.field.fieldSize + 7) / 8
}

internal fun ECParameterSpec.decodePoint(bytes: ByteArray): ECPoint {
    val fieldSize = curveOrderSize()
    return when (bytes[0].toInt()) {
        0x02, // compressed evenY
        0x03, // compressed oddY
             -> {
            check(bytes.size == fieldSize + 1) { "Wrong compressed key size ${bytes.size}" }
            val p = (curve.field as ECFieldFp).p
            val a = curve.a
            val b = curve.b
            val x = BigInteger(1, bytes.copyOfRange(1, bytes.size))
            var y = x.multiply(x).add(a).multiply(x).add(b).mod(p).modSqrt(p)
            if (y.testBit(0) != (bytes[0].toInt() == 0x03)) {
                y = p.subtract(y)
            }
            ECPoint(x, y)
        }
        0x04, // uncompressed
             -> {
            check(bytes.size == fieldSize * 2 + 1) { "Wrong uncompressed key size ${bytes.size}" }
            val x = bytes.copyOfRange(1, fieldSize + 1)
            val y = bytes.copyOfRange(fieldSize + 1, fieldSize + 1 + fieldSize)
            ECPoint(BigInteger(1, x), BigInteger(1, y))
        }
        else -> error("Unsupported key type ${bytes[0].toInt()}")
    }
}

internal fun BigInteger.modSqrt(p: BigInteger): BigInteger {
    check(p.testBit(0) && p.testBit(1)) { "Unsupported curve modulus" }  // p ≡ 3 (mod 4)
    return modPow(p.add(BigInteger.ONE).shiftRight(2), p) // Tonelli-Shanks
}

private fun JAlgorithmParameters.curveName(): String {
    return getParameterSpec(ECGenParameterSpec::class.java).name
}
