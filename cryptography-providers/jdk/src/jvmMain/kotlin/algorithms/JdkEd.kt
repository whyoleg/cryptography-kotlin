package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.Ed
import dev.whyoleg.cryptography.materials.key.KeyDecoder
import dev.whyoleg.cryptography.materials.key.KeyGenerator
import dev.whyoleg.cryptography.providers.jdk.JKeyPair
import dev.whyoleg.cryptography.providers.jdk.JKeyPairGenerator
import dev.whyoleg.cryptography.providers.jdk.JPrivateKey
import dev.whyoleg.cryptography.providers.jdk.JPublicKey
import dev.whyoleg.cryptography.providers.jdk.JdkCryptographyState
import dev.whyoleg.cryptography.providers.jdk.materials.JdkEncodableKey
import dev.whyoleg.cryptography.providers.jdk.materials.JdkKeyPairGenerator
import dev.whyoleg.cryptography.providers.jdk.materials.JdkPrivateKeyDecoder
import dev.whyoleg.cryptography.providers.jdk.materials.JdkPublicKeyDecoder
import dev.whyoleg.cryptography.providers.jdk.materials.unwrapPem
import dev.whyoleg.cryptography.providers.jdk.materials.wrapPem
import dev.whyoleg.cryptography.serialization.pem.PemLabel
//import java.security.spec.XECPublicKeySpec // TODO: for raw encoding

internal sealed class JdkEd<PublicK : Ed.PublicKey, PrivateK : Ed.PrivateKey, KP : Ed.KeyPair<PublicK, PrivateK>>(
    protected val state: JdkCryptographyState,
) : Ed<PublicK, PrivateK, KP> {
    protected abstract fun JPublicKey.convert(): PublicK
    protected abstract fun JPrivateKey.convert(): PrivateK
    protected abstract fun JKeyPair.convert(): KP

    final override fun publicKeyDecoder(curve: Ed.Curve): KeyDecoder<Ed.PublicKey.Format, PublicK> {
        return EdPublicKeyDecoder(curve.jdkName)
    }

    final override fun privateKeyDecoder(curve: Ed.Curve): KeyDecoder<Ed.PrivateKey.Format, PrivateK> {
        return EdPrivateKeyDecoder(curve.jdkName)
    }

    final override fun keyPairGenerator(curve: Ed.Curve): KeyGenerator<KP> {
        return EdKeyPairGenerator(curve.jdkName)
    }

    private val Ed.Curve.jdkName: String get() = name

    private inner class EdKeyPairGenerator(
        private val algorithm: String,
    ) : JdkKeyPairGenerator<KP>(state, algorithm) {
        override fun JKeyPairGenerator.init() {
            //initialize(null, state.secureRandom) // TODO
        }

        override fun JKeyPair.convert(): KP = with(this@JdkEd) { convert() }
    }

    private inner class EdPublicKeyDecoder(
        private val algorithm: String,
    ) : JdkPublicKeyDecoder<Ed.PublicKey.Format, PublicK>(state, algorithm) {
        override fun JPublicKey.convert(): PublicK = with(this@JdkEd) { convert() }

        override fun decodeFromByteArrayBlocking(format: Ed.PublicKey.Format, bytes: ByteArray): PublicK = when (format) {
            Ed.PublicKey.Format.JWK -> error("$format is not supported")
           /* Ed.PublicKey.Format.RAW -> keyFactory.use {
                it.generatePublic(XECPublicKeySpec(NamedParameterSpec(algorithm), bytes))
            }.convert()*/ // TODO: for raw encoding
            Ed.PublicKey.Format.RAW -> TODO("Todo: raw encoding")
            Ed.PublicKey.Format.DER -> decodeFromDer(bytes)
            Ed.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class EdPrivateKeyDecoder(
        private val algorithm: String,
    ) : JdkPrivateKeyDecoder<Ed.PrivateKey.Format, PrivateK>(state, algorithm) {
        override fun JPrivateKey.convert(): PrivateK = with(this@JdkEd) { convert() }

        override fun decodeFromByteArrayBlocking(format: Ed.PrivateKey.Format, bytes: ByteArray): PrivateK = when (format) {
            Ed.PrivateKey.Format.JWK -> error("$format is not supported")
            Ed.PrivateKey.Format.RAW -> TODO("Todo: raw encoding")
            /*Ed.PrivateKey.Format.RAW -> keyFactory.use {
                it.generatePrivate(XECPrivateKeySpec(NamedParameterSpec(algorithm), bytes))
            }.convert()*/  // TODO: for raw encoding
            Ed.PrivateKey.Format.DER -> decodeFromDer(bytes)
            Ed.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }
    }

    protected abstract class BaseEdPublicKey(
        private val key: JPublicKey,
    ) : Ed.PublicKey, JdkEncodableKey<Ed.PublicKey.Format>(key) {
        final override fun encodeToByteArrayBlocking(format: Ed.PublicKey.Format): ByteArray = when (format) {
            Ed.PublicKey.Format.JWK -> error("$format is not supported")
            Ed.PublicKey.Format.RAW -> TODO("Todo: raw encoding")
//            Ed.PublicKey.Format.RAW -> (key as XECPublicKey).encoded
            Ed.PublicKey.Format.DER -> encodeToDer()
            Ed.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
            else -> TODO()
        }
    }

    protected abstract class BaseEdPrivateKey(
        private val key: JPrivateKey,
    ) : Ed.PrivateKey, JdkEncodableKey<Ed.PrivateKey.Format>(key) {
        final override fun encodeToByteArrayBlocking(format: Ed.PrivateKey.Format): ByteArray = when (format) {
            Ed.PrivateKey.Format.JWK -> error("$format is not supported")
            Ed.PrivateKey.Format.RAW -> TODO("Todo: raw encoding")
//            Ed.PrivateKey.Format.RAW -> (key as XECPrivateKey).encoded
            Ed.PrivateKey.Format.DER -> encodeToDer()
            Ed.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
            else -> TODO()
        }
    }
}
