/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import javax.crypto.interfaces.*
import javax.crypto.spec.*

internal class JdkDh(
    private val state: JdkCryptographyState,
) : DH {
    override fun publicKeyDecoder(): Decoder<DH.PublicKey.Format, DH.PublicKey> = DhPublicKeyDecoder()

    override fun privateKeyDecoder(): Decoder<DH.PrivateKey.Format, DH.PrivateKey> = DhPrivateKeyDecoder()

    override fun parametersDecoder(): Decoder<DH.Parameters.Format, DH.Parameters> = DhParametersDecoder()

    override fun parametersGenerator(primeSize: BinarySize, privateValueSize: BinarySize?): DH.ParametersGenerator =
        DhParametersGenerator(primeSize, privateValueSize)

    private inner class DhKeyPairGenerator(
        private val parameters: DHParameterSpec,
    ) : JdkKeyPairGenerator<DH.KeyPair>(state, "DH") {
        override fun JKeyPairGenerator.init() {
            initialize(parameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): DH.KeyPair {
            val publicKey = DhPublicKey(public as DHPublicKey)
            return DhKeyPair(publicKey, DhPrivateKey(private as DHPrivateKey, publicKey))
        }
    }

    private inner class DhPublicKeyDecoder :
        JdkPublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>(state, "DH") {

        fun fromPrivateKey(privateKey: DHPrivateKey): DH.PublicKey {
            val params = privateKey.params
            val y = params.g.modPow(privateKey.x, params.p)
            return decode(DHPublicKeySpec(y, params.p, params.g))
        }

        override fun JPublicKey.convert(): DH.PublicKey {
            check(this is DHPublicKey)
            return DhPublicKey(this)
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
            return DhPrivateKey(this, null)
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
    ) : DH.PublicKey, JdkEncodableKey<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("DH")

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
    ) : DH.PrivateKey, JdkEncodableKey<DH.PrivateKey.Format>(key), SharedSecretGenerator<DH.PublicKey> {
        private val keyAgreement = state.keyAgreement("DH")

        override fun getPublicKeyBlocking(): DH.PublicKey {
            if (publicKey == null) {
                publicKey = DhPublicKeyDecoder().fromPrivateKey(key)
            }
            return publicKey!!
        }

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

    private inner class DhParametersDecoder : Decoder<DH.Parameters.Format, DH.Parameters> {
        override fun decodeFromByteArrayBlocking(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters = when (format) {
            DH.Parameters.Format.DER -> decodeFromDer(bytes)
            DH.Parameters.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.DhParameters, bytes))
        }

        private fun decodeFromDer(bytes: ByteArray): DH.Parameters = JdkDhParameters(
            state.algorithmParameters("DH").also { it.init(bytes) }
        )
    }

    private inner class DhParametersGenerator(
        private val primeSize: BinarySize,
        private val privateValueSize: BinarySize?,
    ) : DH.ParametersGenerator {
        private val algorithmParameterGenerator = state.algorithmParameterGenerator("DH")

        override fun generateParametersBlocking(): DH.Parameters = algorithmParameterGenerator.use { paramGen ->
            if (privateValueSize != null) {
                paramGen.init(DHGenParameterSpec(primeSize.inBits, privateValueSize.inBits), state.secureRandom)
            } else {
                paramGen.init(primeSize.inBits, state.secureRandom)
            }
            JdkDhParameters(paramGen.generateParameters())
        }
    }

    private inner class JdkDhParameters(
        private val parameters: JAlgorithmParameters,
    ) : DH.Parameters {
        override fun keyPairGenerator(): KeyGenerator<DH.KeyPair> {
            return DhKeyPairGenerator(parameters.getParameterSpec(DHParameterSpec::class.java))
        }

        override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray = when (format) {
            DH.Parameters.Format.DER -> parameters.encoded
            DH.Parameters.Format.PEM -> wrapPem(PemLabel.DhParameters, parameters.encoded)
        }
    }
}
