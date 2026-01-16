/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
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
    override fun publicKeyDecoder(): KeyDecoder<DH.PublicKey.Format, DH.PublicKey> = DhPublicKeyDecoder()

    override fun privateKeyDecoder(): KeyDecoder<DH.PrivateKey.Format, DH.PrivateKey> = DhPrivateKeyDecoder()

    override fun parametersDecoder(): MaterialDecoder<DH.Parameters.Format, DH.Parameters> = DhParametersDecoder()

    override fun parametersGenerator(primeSize: BinarySize): MaterialGenerator<DH.Parameters> =
        DhParametersGenerator(primeSize)

    private fun DHParameterSpec.toParameters(): DH.Parameters {
        val pBytes = p.toByteArray().trimLeadingZeros()
        val gBytes = g.toByteArray().trimLeadingZeros()
        return JdkDhParameters(pBytes.decodeToBigInt(), gBytes.decodeToBigInt())
    }

    private inner class DhKeyPairGenerator(
        private val dhParameters: DHParameterSpec,
        private val parameters: DH.Parameters,
    ) : JdkKeyPairGenerator<DH.KeyPair>(state, "DH") {
        override fun JKeyPairGenerator.init() {
            initialize(dhParameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): DH.KeyPair {
            val publicKey = DhPublicKey(public as DHPublicKey, parameters)
            return DhKeyPair(publicKey, DhPrivateKey(private as DHPrivateKey, publicKey, parameters))
        }
    }

    private inner class DhPublicKeyDecoder :
        JdkPublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>(state, "DH") {
        override fun JPublicKey.convert(): DH.PublicKey {
            check(this is DHPublicKey)
            return DhPublicKey(this, params.toParameters())
        }

        override fun decodeFromByteArrayBlocking(format: DH.PublicKey.Format, bytes: ByteArray): DH.PublicKey = when (format) {
            DH.PublicKey.Format.DER -> decodeFromDer(bytes)
            DH.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class DhPrivateKeyDecoder :
        JdkPrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>(state, "DH") {
        override fun JPrivateKey.convert(): DH.PrivateKey {
            check(this is DHPrivateKey)
            return DhPrivateKey(this, null, params.toParameters())
        }

        override fun decodeFromByteArrayBlocking(format: DH.PrivateKey.Format, bytes: ByteArray): DH.PrivateKey = when (format) {
            DH.PrivateKey.Format.DER -> decodeFromDer(bytes)
            DH.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }
    }

    private class DhKeyPair(
        override val publicKey: DH.PublicKey,
        override val privateKey: DH.PrivateKey,
    ) : DH.KeyPair

    private inner class DhPublicKey(
        val key: DHPublicKey,
        override val parameters: DH.Parameters,
    ) : DH.PublicKey, JdkEncodableKey<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("DH")

        override val y: BigInt get() = key.y.toByteArray().trimLeadingZeros().decodeToBigInt()

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.key, key)
        }

        override fun encodeToByteArrayBlocking(format: DH.PublicKey.Format): ByteArray = when (format) {
            DH.PublicKey.Format.DER -> encodeToDer()
            DH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class DhPrivateKey(
        val key: DHPrivateKey,
        private var publicKey: DH.PublicKey?,
        override val parameters: DH.Parameters,
    ) : DH.PrivateKey, JdkEncodableKey<DH.PrivateKey.Format>(key), SharedSecretGenerator<DH.PublicKey> {
        private val keyAgreement = state.keyAgreement("DH")

        override val x: BigInt get() = key.x.toByteArray().trimLeadingZeros().decodeToBigInt()

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }

        override fun encodeToByteArrayBlocking(format: DH.PrivateKey.Format): ByteArray = when (format) {
            DH.PrivateKey.Format.DER -> encodeToDer()
            DH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }

    private inner class DhParametersDecoder : MaterialDecoder<DH.Parameters.Format, DH.Parameters> {
        override fun decodeFromByteArrayBlocking(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters {
            val derBytes = when (format) {
                DH.Parameters.Format.DER -> bytes
                DH.Parameters.Format.PEM -> unwrapDhParametersPem(bytes)
            }
            val (prime, base) = decodeDhParametersFromDer(derBytes)
            return JdkDhParameters(prime, base)
        }
    }

    private inner class DhParametersGenerator(
        private val primeSize: BinarySize,
    ) : MaterialGenerator<DH.Parameters> {
        private val algorithmParameterGenerator = state.algorithmParameterGenerator("DH")

        override fun generateBlocking(): DH.Parameters = algorithmParameterGenerator.use { paramGen ->
            paramGen.init(primeSize.inBits, state.secureRandom)
            val algorithmParameters = paramGen.generateParameters()
            val params = algorithmParameters.getParameterSpec(DHParameterSpec::class.java)

            val p = params.p.toByteArray().trimLeadingZeros().decodeToBigInt()
            val g = params.g.toByteArray().trimLeadingZeros().decodeToBigInt()

            JdkDhParameters(p, g)
        }
    }

    private inner class JdkDhParameters(
        override val p: BigInt,
        override val g: BigInt,
    ) : DH.Parameters {
        override fun keyPairGenerator(): KeyGenerator<DH.KeyPair> {
            val spec = DHParameterSpec(
                p.encodeToByteArray().let { BigInteger(1, it) },
                g.encodeToByteArray().let { BigInteger(1, it) }
            )
            return DhKeyPairGenerator(spec, this)
        }

        override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray = when (format) {
            DH.Parameters.Format.DER -> encodeDhParametersToDer(p, g)
            DH.Parameters.Format.PEM -> wrapDhParametersPem(encodeDhParametersToDer(p, g))
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
