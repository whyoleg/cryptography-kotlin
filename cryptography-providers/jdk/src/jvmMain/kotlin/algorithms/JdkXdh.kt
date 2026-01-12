/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.serialization.builtins.*

internal class JdkXdh(private val state: JdkCryptographyState) : XDH {
    private val XDH.Curve.oid: ObjectIdentifier
        get() = when (this) {
            XDH.Curve.X25519 -> ObjectIdentifier.X25519
            XDH.Curve.X448   -> ObjectIdentifier.X448
        }

    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> = PublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> = PrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> = KeyPairGenerator(curve)

    private inner class PublicKeyDecoder(
        private val curve: XDH.Curve,
    ) : JdkPublicKeyDecoder<XDH.PublicKey.Format, XDH.PublicKey>(state, curve.name) {
        override fun JPublicKey.convert(): XDH.PublicKey = XdhPublicKey(state, this, curve)

        override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
            XDH.PublicKey.Format.JWK -> error("JWK is not supported")
            XDH.PublicKey.Format.RAW -> decodeFromDer(
                wrapSubjectPublicKeyInfo(UnknownKeyAlgorithmIdentifier(curve.oid), bytes)
            )
            XDH.PublicKey.Format.DER -> decodeFromDer(bytes)
            XDH.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class PrivateKeyDecoder(
        private val curve: XDH.Curve,
    ) : JdkPrivateKeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey>(state, curve.name) {
        override fun JPrivateKey.convert(): XDH.PrivateKey = XdhPrivateKey(state, this, null, curve)

        override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
            XDH.PrivateKey.Format.JWK -> error("JWK is not supported")
            XDH.PrivateKey.Format.RAW -> {
                // EdDSA/XDH RAW private keys need to be wrapped in OCTET STRING for PKCS#8
                val wrappedKey = Der.encodeToByteArray(ByteArraySerializer(), bytes)
                decodeFromDer(
                    wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(curve.oid), wrappedKey)
                )
            }
            XDH.PrivateKey.Format.DER -> decodeFromDer(bytes)
            XDH.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
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
            XDH.PublicKey.Format.RAW -> {
                val der = encodeToDer()
                unwrapSubjectPublicKeyInfo(curve.oid, der)
            }
            XDH.PublicKey.Format.DER -> encodeToDer()
            XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class XdhPrivateKey(
        private val state: JdkCryptographyState,
        val key: JPrivateKey,
        @Volatile
        private var publicKey: XDH.PublicKey?,
        private val curve: XDH.Curve,
    ) : XDH.PrivateKey, JdkEncodableKey<XDH.PrivateKey.Format>(key), SharedSecretGenerator<XDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this

        override fun getPublicKeyBlocking(): XDH.PublicKey {
            publicKey?.let { return it }
            val spec = BouncyCastleBridge.deriveXDHPublicKeySpec(key)
                ?: error("Getting public key from private key for XDH is not supported in JDK without BouncyCastle APIs")
            val publicKey = XdhPublicKey(state, state.keyFactory("XDH").use { it.generatePublic(spec) }, curve)
            this.publicKey = publicKey
            return publicKey
        }

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.JWK -> error("JWK is not supported")
            XDH.PrivateKey.Format.RAW -> {
                val der = encodeToDer()
                unwrapPrivateKeyInfoForEdDsaXdh(curve.oid, der)
            }
            XDH.PrivateKey.Format.DER -> encodeToDer()
            XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}
