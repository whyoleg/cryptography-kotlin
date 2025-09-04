package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*

internal class JdkEdDSA(private val state: JdkCryptographyState) : EdDSA {
    private fun curveName(curve: EdDSA.Curve): String = when (curve) {
        EdDSA.Curve.Ed25519 -> "Ed25519"
        EdDSA.Curve.Ed448   -> "Ed448"
    }
    private fun oid(curve: EdDSA.Curve): ObjectIdentifier = when (curve) {
        EdDSA.Curve.Ed25519 -> ObjectIdentifier("1.3.101.112")
        EdDSA.Curve.Ed448   -> ObjectIdentifier("1.3.101.113")
    }

    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> =
        object : JdkPublicKeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey>(state, curveName(curve)) {
            override fun JPublicKey.convert(): EdDSA.PublicKey = EdDsaPublicKey(state, this)

            override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
                EdDSA.PublicKey.Format.JWK -> error("JWK is not supported")
                EdDSA.PublicKey.Format.RAW -> decodeFromDer(
                    wrapSubjectPublicKeyInfo(UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                EdDSA.PublicKey.Format.DER -> decodeFromDer(bytes)
                EdDSA.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
            }
        }

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> =
        object : JdkPrivateKeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey>(state, curveName(curve)) {
            override fun JPrivateKey.convert(): EdDSA.PrivateKey = EdDsaPrivateKey(state, this)

            override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
                EdDSA.PrivateKey.Format.JWK -> error("JWK is not supported")
                EdDSA.PrivateKey.Format.RAW -> decodeFromDer(
                    wrapPrivateKeyInfo(
                        0,
                        UnknownKeyAlgorithmIdentifier(oid(curve)),
                        bytes
                    )
                )
                EdDSA.PrivateKey.Format.DER -> decodeFromDer(bytes)
                EdDSA.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
            }
        }

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> = object : JdkKeyPairGenerator<EdDSA.KeyPair>(state, curveName(curve)) {
        override fun JKeyPairGenerator.init() {
            // no additional init required
        }

        override fun JKeyPair.convert(): EdDSA.KeyPair = EdDsaKeyPair(
            EdDsaPublicKey(state, public),
            EdDsaPrivateKey(state, private),
        )
    }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        private val state: JdkCryptographyState,
        private val key: JPublicKey,
    ) : EdDSA.PublicKey, JdkEncodableKey<EdDSA.PublicKey.Format>(key) {
        override fun signatureVerifier(): SignatureVerifier {
            return JdkSignatureVerifier(state, key, "EdDSA", null)
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.JWK -> error("JWK is not supported")
            EdDSA.PublicKey.Format.RAW -> {
                val der = encodeToDer()
                // unwrap SPKI to raw for known OIDs
                try { unwrapSubjectPublicKeyInfo(ObjectIdentifier("1.3.101.112"), der) } catch (_: Throwable) {
                    unwrapSubjectPublicKeyInfo(ObjectIdentifier("1.3.101.113"), der)
                }
            }
            EdDSA.PublicKey.Format.DER -> encodeToDer()
            EdDSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private class EdDsaPrivateKey(
        private val state: JdkCryptographyState,
        private val key: JPrivateKey,
    ) : EdDSA.PrivateKey, JdkEncodableKey<EdDSA.PrivateKey.Format>(key) {
        override fun signatureGenerator(): SignatureGenerator {
            return JdkSignatureGenerator(state, key, "EdDSA", null)
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.JWK -> error("JWK is not supported")
            EdDSA.PrivateKey.Format.RAW -> {
                val der = encodeToDer()
                // unwrap PKCS#8 to raw for known OIDs
                try { unwrapPrivateKeyInfo(ObjectIdentifier("1.3.101.112"), der) } catch (_: Throwable) {
                    unwrapPrivateKeyInfo(ObjectIdentifier("1.3.101.113"), der)
                }
            }
            EdDSA.PrivateKey.Format.DER -> encodeToDer()
            EdDSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }
}
