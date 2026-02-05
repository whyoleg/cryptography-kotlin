/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal class JdkXdh(private val state: JdkCryptographyState) : XDH {
    private val XDH.Curve.identifier: AlgorithmIdentifier
        get() = when (this) {
            XDH.Curve.X25519 -> X25519AlgorithmIdentifier
            XDH.Curve.X448   -> X448AlgorithmIdentifier
        }

    override fun publicKeyDecoder(curve: XDH.Curve): Decoder<XDH.PublicKey.Format, XDH.PublicKey> = PublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: XDH.Curve): Decoder<XDH.PrivateKey.Format, XDH.PrivateKey> = PrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> = KeyPairGenerator(curve)

    private inner class PublicKeyDecoder(
        private val curve: XDH.Curve,
    ) : JdkPublicKeyDecoder<XDH.PublicKey.Format, XDH.PublicKey>(state, curve.name) {

        fun fromPrivateKey(privateKey: JPrivateKey): XDH.PublicKey {
            return BouncyCastleBridge.deriveXdhPublicKey(privateKey, curve)
                ?.let { (pk, raw) -> pk?.convert() ?: raw?.let(::decodeFromRaw) }
                ?: error("Getting public key from private key for XDH is not supported in JDK without BouncyCastle APIs")
        }

        fun fromEncodedPrivateKey(bytes: ByteArray): XDH.PublicKey? =
            getPublicKeyFromPrivateKeyPkcs8(curve.identifier.algorithm, bytes)?.let(::decodeFromRaw)

        override fun JPublicKey.convert(): XDH.PublicKey = XdhPublicKey(state, this, curve)

        override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
            XDH.PublicKey.Format.JWK -> error("JWK is not supported")
            XDH.PublicKey.Format.RAW -> decodeFromRaw(bytes)
            XDH.PublicKey.Format.DER -> decodeFromDer(bytes)
            XDH.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }

        private fun decodeFromRaw(bytes: ByteArray) = decodeFromDer(wrapSubjectPublicKeyInfo(curve.identifier, bytes))
    }

    private inner class PrivateKeyDecoder(
        private val curve: XDH.Curve,
    ) : JdkPrivateKeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey>(state, curve.name) {
        override fun JPrivateKey.convert(): XDH.PrivateKey = XdhPrivateKey(state, this, null, curve)

        override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
            XDH.PrivateKey.Format.JWK -> error("JWK is not supported")
            XDH.PrivateKey.Format.RAW -> decodeFromDer(wrapCurvePrivateKeyInfo(0, curve.identifier, bytes))
            XDH.PrivateKey.Format.DER -> decodeFromDer(bytes)
            XDH.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }

        override fun decodeFromDer(input: ByteArray): XDH.PrivateKey {
            val privateKey = decodeFromDerRaw(input)
            return XdhPrivateKey(
                state = state,
                key = privateKey,
                publicKey = PublicKeyDecoder(curve).fromEncodedPrivateKey(input),
                curve = curve
            )
        }
    }

    private inner class KeyPairGenerator(
        private val curve: XDH.Curve,
    ) : JdkKeyPairGenerator<XDH.KeyPair>(state, curve.name) {
        override fun JKeyPairGenerator.init() {
            // no additional init required
        }

        override fun JKeyPair.convert(): XDH.KeyPair {
            val publicKey = XdhPublicKey(state, public, curve)
            return XdhKeyPair(
                publicKey,
                XdhPrivateKey(state, private, publicKey, curve),
            )
        }
    }

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private inner class XdhPublicKey(
        private val state: JdkCryptographyState,
        val key: JPublicKey,
        private val curve: XDH.Curve,
    ) : XDH.PublicKey, JdkEncodableKey<XDH.PublicKey.Format>(key), SharedSecretGenerator<XDH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.key, key)
        }

        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray = when (format) {
            XDH.PublicKey.Format.JWK -> error("JWK is not supported")
            XDH.PublicKey.Format.RAW -> unwrapSubjectPublicKeyInfo(curve.identifier.algorithm, encodeToDer())
            XDH.PublicKey.Format.DER -> encodeToDer()
            XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class XdhPrivateKey(
        private val state: JdkCryptographyState,
        val key: JPrivateKey,
        private var publicKey: XDH.PublicKey?,
        private val curve: XDH.Curve,
    ) : XDH.PrivateKey, JdkEncodableKey<XDH.PrivateKey.Format>(key), SharedSecretGenerator<XDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this

        override fun getPublicKeyBlocking(): XDH.PublicKey {
            if (publicKey == null) {
                publicKey = PublicKeyDecoder(curve).fromPrivateKey(key)
            }
            return publicKey!!
        }

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.JWK -> error("JWK is not supported")
            XDH.PrivateKey.Format.RAW -> unwrapCurvePrivateKeyInfo(curve.identifier.algorithm, encodeToDer())
            XDH.PrivateKey.Format.DER -> encodeToDer()
            XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}
