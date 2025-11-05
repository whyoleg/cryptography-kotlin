/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.math.*
import java.security.interfaces.*
import java.security.spec.*

internal sealed class JdkEc<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey<PublicK>, KP : EC.KeyPair<PublicK, PrivateK>>(
    protected val state: JdkCryptographyState,
) : EC<PublicK, PrivateK, KP> {
    protected abstract val wrapPublicKey: (JPublicKey) -> PublicK
    protected abstract val wrapPrivateKey: (JPrivateKey, PublicK?) -> PrivateK
    protected abstract val wrapKeyPair: (PublicK, PrivateK) -> KP

    private fun algorithmParameters(spec: AlgorithmParameterSpec): JAlgorithmParameters {
        return state.algorithmParameters("EC").also { it.init(spec) }
    }

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

        override fun JKeyPair.convert(): KP {
            val publicKey = wrapPublicKey(public)
            val privateKey = wrapPrivateKey(private, publicKey)
            return wrapKeyPair(publicKey, privateKey)
        }
    }

    private inner class EcPublicKeyDecoder(
        private val curveName: String,
    ) : JdkPublicKeyDecoder<EC.PublicKey.Format, PublicK>(state, "EC") {

        fun fromPrivateKey(privateKey: ECPrivateKey): PublicK = decode(
            BouncyCastleBridge.derivePublicKey(privateKey, curveName) ?: error(
                "Getting public key from private key for EC is not supported in JDK without BouncyCastle APIs"
            )
        )

        fun fromEncodedPrivateKey(bytes: ByteArray): PublicK? =
            getEcPublicKeyFromPrivateKeyPkcs8(bytes)?.let(::decodeFromRaw)

        override fun JPublicKey.convert(): PublicK {
            check(this is ECPublicKey)

            val keyCurve = algorithmParameters(params).curveName()
            check(curveName == keyCurve) { "Key curve $keyCurve is not equal to expected curve $curveName" }

            return wrapPublicKey(this)
        }

        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): PublicK = when (format) {
            EC.PublicKey.Format.JWK            -> error("$format is not supported")
            EC.PublicKey.Format.RAW            -> decodeFromRaw(bytes)
            EC.PublicKey.Format.RAW.Compressed -> decodeFromRaw(bytes)
            EC.PublicKey.Format.DER            -> decodeFromDer(bytes)
            EC.PublicKey.Format.PEM            -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }

        private fun decodeFromRaw(bytes: ByteArray): PublicK {
            check(bytes.isNotEmpty()) { "Encoded key is empty!" }
            val parameters = algorithmParameters(ECGenParameterSpec(curveName)).getParameterSpec(ECParameterSpec::class.java)
            val point = parameters.decodePoint(bytes)

            return decode(ECPublicKeySpec(point, parameters))
        }
    }

    private inner class EcPrivateKeyDecoder(
        private val curveName: String,
    ) : JdkPrivateKeyDecoder<EC.PrivateKey.Format, PrivateK>(state, "EC") {
        override fun JPrivateKey.convert(): PrivateK = create(this, null)

        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): PrivateK = when (format) {
            EC.PrivateKey.Format.JWK      -> error("$format is not supported")
            EC.PrivateKey.Format.RAW      -> {
                val parameters = algorithmParameters(ECGenParameterSpec(curveName)).getParameterSpec(ECParameterSpec::class.java)
                // decode as positive value
                decode(ECPrivateKeySpec(BigInteger(1, bytes), parameters))
            }
            EC.PrivateKey.Format.DER      -> decodeFromDer(bytes)
            EC.PrivateKey.Format.PEM      -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
            EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertEcPrivateKeyFromSec1ToPkcs8(bytes))
            EC.PrivateKey.Format.PEM.SEC1 -> decodeFromDer(convertEcPrivateKeyFromSec1ToPkcs8(unwrapPem(PemLabel.EcPrivateKey, bytes)))
        }

        override fun decodeFromDer(input: ByteArray): PrivateK {
            val privateKey = decodeFromDerRaw(input)
            return create(
                privateKey = privateKey,
                publicKey = EcPublicKeyDecoder(curveName).fromEncodedPrivateKey(input)
            )
        }

        private fun create(privateKey: JPrivateKey, publicKey: PublicK?): PrivateK {
            check(privateKey is ECPrivateKey)

            val keyCurve = algorithmParameters(privateKey.params).curveName()
            check(curveName == keyCurve) { "Key curve $keyCurve is not equal to expected curve $curveName" }

            return wrapPrivateKey(privateKey, publicKey)
        }
    }

    protected abstract class BaseEcPublicKey(
        val key: JPublicKey,
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
                output[0] = if (key.w.affineY.testBit(0)) 0x03 else 0x02
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

    protected abstract inner class BaseEcPrivateKey(
        val key: JPrivateKey,
        private var publicKey: PublicK?,
    ) : EC.PrivateKey<PublicK>, JdkEncodableKey<EC.PrivateKey.Format>(key) {
        override fun getPublicKeyBlocking(): PublicK {
            if (publicKey == null) {
                key as ECPrivateKey
                val curveName = algorithmParameters(key.params).curveName()
                publicKey = EcPublicKeyDecoder(curveName).fromPrivateKey(key)
            }
            return publicKey!!
        }

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
            EC.PrivateKey.Format.DER.SEC1 -> convertEcPrivateKeyFromPkcs8ToSec1(encodeToDer())
            EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, convertEcPrivateKeyFromPkcs8ToSec1(encodeToDer()))
        }
    }
}

internal fun ECParameterSpec.curveOrderSize(): Int {
    return (curve.field.fieldSize + 7) / 8
}

/**
 * Decodes an elliptic curve point from its byte representation.
 *
 * This implementation follows ANSI X9.62 standard for point encoding:
 * - 0x02/0x03: Compressed point format (x-coordinate + y-parity bit)
 * - 0x04: Uncompressed point format (x-coordinate + y-coordinate)
 *
 * For compressed points, the y-coordinate is computed by solving the curve equation:
 * y² = x³ + ax + b (mod p)
 *
 * References:
 * - ANSI X9.62-2005: Public Key Cryptography for the Financial Services Industry - The Elliptic Curve Digital Signature Algorithm (ECDSA)
 * - SEC 1: Elliptic Curve Cryptography, Section 2.3.4: Octet-String-to-Elliptic-Curve-Point Conversion
 *   https://www.secg.org/sec1-v2.pdf
 */
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

/**
 * Computes the modular square root using the Tonelli-Shanks algorithm.
 *
 * This implementation is optimized for the case where p ≡ 3 (mod 4),
 * which applies to the NIST curves (P-256, P-384, P-521).
 *
 * For such primes, the square root can be computed as: x^((p+1)/4) mod p
 *
 * References:
 * - Handbook of Applied Cryptography, Algorithm 3.36
 * - NIST SP 800-186: Recommendations for Discrete Logarithm-based Cryptography
 */
internal fun BigInteger.modSqrt(p: BigInteger): BigInteger {
    check(p.testBit(0) && p.testBit(1)) { "Unsupported curve modulus" }  // p ≡ 3 (mod 4)
    return modPow(p.add(BigInteger.ONE).shiftRight(2), p) // Tonelli-Shanks
}

private fun JAlgorithmParameters.curveName(): String {
    return getParameterSpec(ECGenParameterSpec::class.java).name
}
