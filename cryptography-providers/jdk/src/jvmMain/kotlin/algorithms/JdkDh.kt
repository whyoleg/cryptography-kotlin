/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.security.spec.*
import javax.crypto.interfaces.*
import javax.crypto.spec.*

internal class JdkDh(private val state: JdkCryptographyState) : DH {
    override fun publicKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PublicKey.Format, DH.PublicKey> {
        return DhPublicKeyDecoder(parameters)
    }

    override fun privateKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PrivateKey.Format, DH.PrivateKey> {
        return DhPrivateKeyDecoder(parameters)
    }

    override fun keyPairGenerator(parameters: DH.Parameters): KeyGenerator<DH.KeyPair> {
        return DhKeyPairGenerator(parameters)
    }

    override fun parametersDecoder(): KeyDecoder<DH.Parameters.Format, DH.Parameters> {
        return DhParametersDecoder()
    }

    override fun parametersGenerator(keySize: Int): KeyGenerator<DH.Parameters> {
        return DhParametersGenerator(keySize)
    }

    private inner class DhParametersGenerator(
        private val keySize: Int,
    ) : JdkKeyPairGenerator<DH.Parameters>(state, "DH") {
        override fun JKeyPairGenerator.init() {
            initialize(keySize, state.secureRandom)
        }

        override fun JKeyPair.convert(): DH.Parameters {
            val publicKey = public as DHPublicKey
            return DhParameters(state, publicKey.params)
        }
    }

    private inner class DhParametersDecoder : KeyDecoder<DH.Parameters.Format, DH.Parameters> {
        override suspend fun decodeFromByteArray(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters {
            return decodeFromByteArrayBlocking(format, bytes)
        }

        override fun decodeFromByteArrayBlocking(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters = when (format) {
            DH.Parameters.Format.DER -> decodeFromDer(bytes)
            DH.Parameters.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.DHParams, bytes))
        }

        private fun decodeFromDer(bytes: ByteArray): DH.Parameters {
            val algorithmParameters = state.algorithmParameters("DH")
            algorithmParameters.init(bytes)
            val parameterSpec = algorithmParameters.getParameterSpec(DHParameterSpec::class.java)
            return DhParameters(state, parameterSpec)
        }
    }

    private inner class DhKeyPairGenerator(
        private val parameters: DH.Parameters,
    ) : JdkKeyPairGenerator<DH.KeyPair>(state, "DH") {
        override fun JKeyPairGenerator.init() {
            val dhParameters = (parameters as DhParameters).parameterSpec
            initialize(dhParameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): DH.KeyPair {
            return DhKeyPair(
                publicKey = DhPublicKey(state, public as DHPublicKey),
                privateKey = DhPrivateKey(state, private as DHPrivateKey)
            )
        }
    }

    private inner class DhPublicKeyDecoder(
        private val parameters: DH.Parameters,
    ) : JdkPublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>(state, "DH") {
        override fun JPublicKey.convert(): DH.PublicKey {
            check(this is DHPublicKey)
            val dhParameters = (parameters as DhParameters).parameterSpec
            check(this.params.p == dhParameters.p && this.params.g == dhParameters.g) {
                "Key parameters do not match expected parameters"
            }
            return DhPublicKey(state, this)
        }

        override fun decodeFromByteArrayBlocking(format: DH.PublicKey.Format, bytes: ByteArray): DH.PublicKey = when (format) {
            DH.PublicKey.Format.DER -> decodeFromDer(bytes)
            DH.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class DhPrivateKeyDecoder(
        private val parameters: DH.Parameters,
    ) : JdkPrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>(state, "DH") {
        override fun JPrivateKey.convert(): DH.PrivateKey {
            check(this is DHPrivateKey)
            val dhParameters = (parameters as DhParameters).parameterSpec
            check(this.params.p == dhParameters.p && this.params.g == dhParameters.g) {
                "Key parameters do not match expected parameters"
            }
            return DhPrivateKey(state, this)
        }

        override fun decodeFromByteArrayBlocking(format: DH.PrivateKey.Format, bytes: ByteArray): DH.PrivateKey = when (format) {
            DH.PrivateKey.Format.DER -> decodeFromDer(bytes)
            DH.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }
    }

    private class DhParameters(
        private val state: JdkCryptographyState,
        val parameterSpec: DHParameterSpec,
    ) : DH.Parameters {
        override suspend fun encodeToByteArray(format: DH.Parameters.Format): ByteArray {
            return encodeToByteArrayBlocking(format)
        }

        override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray = when (format) {
            DH.Parameters.Format.DER -> encodeToDerParameters()
            DH.Parameters.Format.PEM -> wrapPem(PemLabel.DHParams, encodeToDerParameters())
        }

        private fun encodeToDerParameters(): ByteArray {
            val algorithmParameters = state.algorithmParameters("DH")
            algorithmParameters.init(parameterSpec)
            return algorithmParameters.encoded
        }
    }

    private class DhKeyPair(
        override val publicKey: DH.PublicKey,
        override val privateKey: DH.PrivateKey,
    ) : DH.KeyPair

    private class DhPublicKey(
        private val state: JdkCryptographyState,
        private val key: DHPublicKey,
    ) : DH.PublicKey, JdkEncodableKey<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        val dhKey: DHPublicKey get() = key
        private val keyAgreement = state.keyAgreement("DH")

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.dhKey, this.key)
        }

        override fun encodeToByteArrayBlocking(format: DH.PublicKey.Format): ByteArray = when (format) {
            DH.PublicKey.Format.DER -> encodeToDer()
            DH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private class DhPrivateKey(
        private val state: JdkCryptographyState,
        private val key: DHPrivateKey,
    ) : DH.PrivateKey, JdkEncodableKey<DH.PrivateKey.Format>(key), SharedSecretGenerator<DH.PublicKey> {
        val dhKey: DHPrivateKey get() = key
        private val keyAgreement = state.keyAgreement("DH")

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, this.key, other.dhKey)
        }

        override fun encodeToByteArrayBlocking(format: DH.PrivateKey.Format): ByteArray = when (format) {
            DH.PrivateKey.Format.DER -> encodeToDer()
            DH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}