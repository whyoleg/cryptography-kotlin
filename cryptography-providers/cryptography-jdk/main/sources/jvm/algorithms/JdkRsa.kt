package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import java.security.spec.*


internal abstract class JdkRsaPublicKeyDecoder<K : RSA.PublicKey>(
    protected val state: JdkCryptographyState,
) : KeyDecoder<RSA.PublicKey.Format, K> {
    private val keyFactory = state.keyFactory("RSA")

    protected abstract fun JPublicKey.convert(): K

    final override fun decodeFromBlocking(format: RSA.PublicKey.Format, input: Buffer): K = when (format) {
        RSA.PublicKey.Format.DER -> keyFactory.use { it.generatePublic(X509EncodedKeySpec(input)) }.convert()
        RSA.PublicKey.Format.JWK -> TODO()
        RSA.PublicKey.Format.PEM -> TODO()
    }

    final override suspend fun decodeFrom(format: RSA.PublicKey.Format, input: Buffer): K {
        return state.execute { decodeFromBlocking(format, input) }
    }
}

internal abstract class JdkRsaPrivateKeyDecoder<K : RSA.PrivateKey>(
    protected val state: JdkCryptographyState,
) : KeyDecoder<RSA.PrivateKey.Format, K> {
    private val keyFactory = state.keyFactory("RSA")

    protected abstract fun JPrivateKey.convert(): K

    final override fun decodeFromBlocking(format: RSA.PrivateKey.Format, input: Buffer): K = when (format) {
        RSA.PrivateKey.Format.DER -> keyFactory.use { it.generatePrivate(PKCS8EncodedKeySpec(input)) }.convert()
        RSA.PrivateKey.Format.JWK -> TODO()
        RSA.PrivateKey.Format.PEM -> TODO()
    }

    final override suspend fun decodeFrom(format: RSA.PrivateKey.Format, input: Buffer): K {
        return state.execute { decodeFromBlocking(format, input) }
    }
}
