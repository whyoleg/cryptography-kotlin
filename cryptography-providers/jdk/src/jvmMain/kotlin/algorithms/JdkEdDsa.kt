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

internal class JdkEdDsa(private val state: JdkCryptographyState) : EdDSA {
    private val EdDSA.Curve.oid: ObjectIdentifier
        get() = when (this) {
            EdDSA.Curve.Ed25519 -> ObjectIdentifier.Ed25519
            EdDSA.Curve.Ed448   -> ObjectIdentifier.Ed448
        }

    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> = PublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> = PrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> = KeyPairGenerator(curve)

    private inner class PublicKeyDecoder(
        private val curve: EdDSA.Curve,
    ) : JdkPublicKeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey>(state, curve.name) {
        override fun JPublicKey.convert(): EdDSA.PublicKey = EdDsaPublicKey(state, this, curve)

        override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
            EdDSA.PublicKey.Format.JWK -> error("JWK is not supported")
            EdDSA.PublicKey.Format.RAW -> decodeFromDer(
                wrapSubjectPublicKeyInfo(UnknownKeyAlgorithmIdentifier(curve.oid), bytes)
            )
            EdDSA.PublicKey.Format.DER -> decodeFromDer(bytes)
            EdDSA.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class PrivateKeyDecoder(
        private val curve: EdDSA.Curve,
    ) : JdkPrivateKeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey>(state, curve.name) {
        override fun JPrivateKey.convert(): EdDSA.PrivateKey = EdDsaPrivateKey(state, this, null, curve)

        override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
            EdDSA.PrivateKey.Format.JWK -> error("JWK is not supported")
            EdDSA.PrivateKey.Format.RAW -> {
                // EdDSA/XDH RAW private keys need to be wrapped in OCTET STRING for PKCS#8
                val wrappedKey = Der.encodeToByteArray(ByteArraySerializer(), bytes)
                decodeFromDer(
                    wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(curve.oid), wrappedKey)
                )
            }
            EdDSA.PrivateKey.Format.DER -> decodeFromDer(bytes)
            EdDSA.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }
    }

    private inner class KeyPairGenerator(
        private val curve: EdDSA.Curve,
    ) : JdkKeyPairGenerator<EdDSA.KeyPair>(state, curve.name) {
        override fun JKeyPairGenerator.init() {
            // no additional init required
        }

        override fun JKeyPair.convert(): EdDSA.KeyPair {
            val publicKey = EdDsaPublicKey(state, public, curve)
            return EdDsaKeyPair(
                publicKey,
                EdDsaPrivateKey(state, private, publicKey, curve),
            )
        }
    }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private inner class EdDsaPublicKey(
        private val state: JdkCryptographyState,
        private val key: JPublicKey,
        private val curve: EdDSA.Curve,
    ) : EdDSA.PublicKey, JdkEncodableKey<EdDSA.PublicKey.Format>(key) {
        override fun signatureVerifier(): SignatureVerifier {
            return JdkSignatureVerifier(state, key, "EdDSA", null)
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.JWK -> error("JWK is not supported")
            EdDSA.PublicKey.Format.RAW -> {
                val der = encodeToDer()
                unwrapSubjectPublicKeyInfo(curve.oid, der)
            }
            EdDSA.PublicKey.Format.DER -> encodeToDer()
            EdDSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class EdDsaPrivateKey(
        private val state: JdkCryptographyState,
        private val key: JPrivateKey,
        @Volatile
        private var publicKey: EdDSA.PublicKey?,
        private val curve: EdDSA.Curve,
    ) : EdDSA.PrivateKey, JdkEncodableKey<EdDSA.PrivateKey.Format>(key) {
        override fun signatureGenerator(): SignatureGenerator {
            return JdkSignatureGenerator(state, key, "EdDSA", null)
        }

        override fun getPublicKeyBlocking(): EdDSA.PublicKey {
            publicKey?.let { return it }
            val spec = BouncyCastleBridge.deriveEdDSAPublicKeySpec(key)
                ?: error("Getting public key from private key for EdDSA is not supported in JDK without BouncyCastle APIs")
            val publicKey = EdDsaPublicKey(state, state.keyFactory("EdDSA").use { it.generatePublic(spec) }, curve)
            this.publicKey = publicKey
            return publicKey
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.JWK -> error("JWK is not supported")
            EdDSA.PrivateKey.Format.RAW -> {
                val der = encodeToDer()
                unwrapPrivateKeyInfoForEdDsaXdh(curve.oid, der)
            }
            EdDSA.PrivateKey.Format.DER -> encodeToDer()
            EdDSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}
