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
            return DhPublicKey(this, JdkDhParameters(params))
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
            return DhPrivateKey(this, null, JdkDhParameters(params))
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

        override val y: BigInt get() = key.y.toKotlinBigInt()

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
        private val keyFactory = state.keyFactory("DH")

        override val x: BigInt get() = key.x.toKotlinBigInt()

        override fun getPublicKeyBlocking(): DH.PublicKey {
            if (publicKey == null) {
                val dhParams = key.params
                val y = dhParams.g.modPow(key.x, dhParams.p)
                val spec = DHPublicKeySpec(y, dhParams.p, dhParams.g)
                publicKey = keyFactory.use { factory ->
                    DhPublicKey(factory.generatePublic(spec) as DHPublicKey, parameters)
                }
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

    private inner class DhParametersDecoder : MaterialDecoder<DH.Parameters.Format, DH.Parameters> {
        override fun decodeFromByteArrayBlocking(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters {
            val derBytes = when (format) {
                DH.Parameters.Format.DER -> bytes
                DH.Parameters.Format.PEM -> unwrapDhParametersPem(bytes)
            }
            val (prime, base) = decodeDhParametersFromDer(derBytes)
            return JdkDhParameters(DHParameterSpec(prime.toJavaBigInteger(), base.toJavaBigInteger()))
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
            JdkDhParameters(params)
        }
    }

    private inner class JdkDhParameters(
        private val spec: DHParameterSpec,
    ) : DH.Parameters {
        override val p: BigInt get() = spec.p.toKotlinBigInt()
        override val g: BigInt get() = spec.g.toKotlinBigInt()

        override fun keyPairGenerator(): KeyGenerator<DH.KeyPair> {
            return DhKeyPairGenerator(spec, this)
        }

        override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray = when (format) {
            DH.Parameters.Format.DER -> encodeDhParametersToDer(p, g)
            DH.Parameters.Format.PEM -> wrapDhParametersPem(encodeDhParametersToDer(p, g))
        }
    }
}
