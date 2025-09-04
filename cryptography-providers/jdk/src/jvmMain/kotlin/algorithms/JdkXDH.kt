package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*

internal class JdkXDH(private val state: JdkCryptographyState) : XDH {
    private fun curveName(curve: XDH.Curve): String = when (curve) {
        XDH.Curve.X25519 -> "X25519"
        XDH.Curve.X448   -> "X448"
    }

    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> =
        object : JdkPublicKeyDecoder<XDH.PublicKey.Format, XDH.PublicKey>(state, curveName(curve)) {
            override fun JPublicKey.convert(): XDH.PublicKey = XdhPublicKey(state, this)

            override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey = when (format) {
                XDH.PublicKey.Format.JWK -> error("JWK is not supported")
                XDH.PublicKey.Format.RAW -> TODO("RAW encoding is not supported yet")
                XDH.PublicKey.Format.DER -> decodeFromDer(bytes)
                XDH.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
            }
        }

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> =
        object : JdkPrivateKeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey>(state, curveName(curve)) {
            override fun JPrivateKey.convert(): XDH.PrivateKey = XdhPrivateKey(state, this)

            override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey = when (format) {
                XDH.PrivateKey.Format.JWK -> error("JWK is not supported")
                XDH.PrivateKey.Format.RAW -> TODO("RAW encoding is not supported yet")
                XDH.PrivateKey.Format.DER -> decodeFromDer(bytes)
                XDH.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
            }
        }

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> = object : JdkKeyPairGenerator<XDH.KeyPair>(state, curveName(curve)) {
        override fun JKeyPairGenerator.init() {
            // no additional init required
        }

        override fun JKeyPair.convert(): XDH.KeyPair = XdhKeyPair(
            XdhPublicKey(state, public),
            XdhPrivateKey(state, private),
        )
    }

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        private val state: JdkCryptographyState,
        val key: JPublicKey,
    ) : XDH.PublicKey, JdkEncodableKey<XDH.PublicKey.Format>(key), SharedSecretGenerator<XDH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.key, key)
        }

        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray = when (format) {
            XDH.PublicKey.Format.JWK -> error("JWK is not supported")
            XDH.PublicKey.Format.RAW -> TODO("RAW encoding is not supported yet")
            XDH.PublicKey.Format.DER -> encodeToDer()
            XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private class XdhPrivateKey(
        private val state: JdkCryptographyState,
        val key: JPrivateKey,
    ) : XDH.PrivateKey, JdkEncodableKey<XDH.PrivateKey.Format>(key), SharedSecretGenerator<XDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray = when (format) {
            XDH.PrivateKey.Format.JWK -> error("JWK is not supported")
            XDH.PrivateKey.Format.RAW -> TODO("RAW encoding is not supported yet")
            XDH.PrivateKey.Format.DER -> encodeToDer()
            XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}
