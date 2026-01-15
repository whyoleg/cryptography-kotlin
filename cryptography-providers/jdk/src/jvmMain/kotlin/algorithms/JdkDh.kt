/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.math.*
import javax.crypto.interfaces.*
import javax.crypto.spec.*

internal class JdkDh(
    private val state: JdkCryptographyState,
) : DH {
    override fun publicKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PublicKey.Format, DH.PublicKey> {
        return DhPublicKeyDecoder(parameters.toSpec())
    }

    override fun privateKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PrivateKey.Format, DH.PrivateKey> {
        return DhPrivateKeyDecoder(parameters.toSpec())
    }

    override fun keyPairGenerator(parameters: DH.Parameters): KeyGenerator<DH.KeyPair> {
        return DhKeyPairGenerator(parameters.toSpec())
    }

    private fun DH.Parameters.toSpec(): DHParameterSpec {
        return DHParameterSpec(
            p.encodeToByteArray().let { BigInteger(1, it) },
            g.encodeToByteArray().let { BigInteger(1, it) }
        )
    }

    private inner class DhKeyPairGenerator(
        private val dhParameters: DHParameterSpec,
    ) : JdkKeyPairGenerator<DH.KeyPair>(state, "DH") {
        override fun JKeyPairGenerator.init() {
            initialize(dhParameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): DH.KeyPair {
            val publicKey = DhPublicKey(public)
            return DhKeyPair(publicKey, DhPrivateKey(private, publicKey))
        }
    }

    private inner class DhPublicKeyDecoder(
        private val dhParameters: DHParameterSpec,
    ) : JdkPublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>(state, "DH") {
        override fun JPublicKey.convert(): DH.PublicKey {
            check(this is DHPublicKey)
            validateParameters(params)
            return DhPublicKey(this)
        }

        override fun decodeFromByteArrayBlocking(format: DH.PublicKey.Format, bytes: ByteArray): DH.PublicKey = when (format) {
            DH.PublicKey.Format.RAW -> {
                val y = BigInteger(1, bytes)
                decode(DHPublicKeySpec(y, dhParameters.p, dhParameters.g))
            }
            DH.PublicKey.Format.DER -> decodeFromDer(bytes)
            DH.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }

        private fun validateParameters(params: DHParameterSpec) {
            check(params.p == dhParameters.p && params.g == dhParameters.g) {
                "Key parameters do not match expected parameters"
            }
        }
    }

    private inner class DhPrivateKeyDecoder(
        private val dhParameters: DHParameterSpec,
    ) : JdkPrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>(state, "DH") {
        override fun JPrivateKey.convert(): DH.PrivateKey {
            check(this is DHPrivateKey)
            validateParameters(params)
            return DhPrivateKey(this, null)
        }

        override fun decodeFromByteArrayBlocking(format: DH.PrivateKey.Format, bytes: ByteArray): DH.PrivateKey = when (format) {
            DH.PrivateKey.Format.RAW -> {
                val x = BigInteger(1, bytes)
                decode(DHPrivateKeySpec(x, dhParameters.p, dhParameters.g))
            }
            DH.PrivateKey.Format.DER -> decodeFromDer(bytes)
            DH.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }

        private fun validateParameters(params: DHParameterSpec) {
            check(params.p == dhParameters.p && params.g == dhParameters.g) {
                "Key parameters do not match expected parameters"
            }
        }
    }

    private class DhKeyPair(
        override val publicKey: DH.PublicKey,
        override val privateKey: DH.PrivateKey,
    ) : DH.KeyPair

    private inner class DhPublicKey(
        val key: JPublicKey,
    ) : DH.PublicKey, JdkEncodableKey<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("DH")

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.key, key)
        }

        override fun encodeToByteArrayBlocking(format: DH.PublicKey.Format): ByteArray = when (format) {
            DH.PublicKey.Format.RAW -> {
                key as DHPublicKey
                // Get the size of p to determine the output size
                val pSize = (key.params.p.bitLength() + 7) / 8
                val yBytes = key.y.toByteArray().trimLeadingZeros()
                // Pad to full size
                yBytes.copyInto(ByteArray(pSize), pSize - yBytes.size)
            }
            DH.PublicKey.Format.DER -> encodeToDer()
            DH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class DhPrivateKey(
        val key: JPrivateKey,
        private var publicKey: DH.PublicKey?,
    ) : DH.PrivateKey, JdkEncodableKey<DH.PrivateKey.Format>(key), SharedSecretGenerator<DH.PublicKey> {
        private val keyAgreement = state.keyAgreement("DH")

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }

        override fun encodeToByteArrayBlocking(format: DH.PrivateKey.Format): ByteArray = when (format) {
            DH.PrivateKey.Format.RAW -> {
                key as DHPrivateKey
                // Get the size of p to determine the output size
                val pSize = (key.params.p.bitLength() + 7) / 8
                val xBytes = key.x.toByteArray().trimLeadingZeros()
                // Pad to full size
                xBytes.copyInto(ByteArray(pSize), pSize - xBytes.size)
            }
            DH.PrivateKey.Format.DER -> encodeToDer()
            DH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}

private fun ByteArray.trimLeadingZeros(): ByteArray {
    val firstNonZero = indexOfFirst { it != 0.toByte() }
    return when {
        firstNonZero < 0 -> byteArrayOf(0)
        firstNonZero == 0 -> this
        else -> copyOfRange(firstNonZero, size)
    }
}
