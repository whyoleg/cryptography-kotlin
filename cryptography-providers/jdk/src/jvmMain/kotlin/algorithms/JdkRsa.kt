/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

//rsa JDK uses slightly different names for hash algorithms
internal fun CryptographyAlgorithmId<Digest>.rsaHashAlgorithmName(): String = when (this) {
    SHA1     -> "SHA-1"
    SHA224   -> "SHA-224"
    SHA256   -> "SHA-256"
    SHA384   -> "SHA-384"
    SHA512   -> "SHA-512"
    SHA3_224 -> "SHA3-224"
    SHA3_256 -> "SHA3-256"
    SHA3_384 -> "SHA3-384"
    SHA3_512 -> "SHA3-512"
    else -> throw IllegalStateException("Unsupported hash algorithm: $this")
}

internal abstract class RsaPublicKeyDecoder<K : RSA.PublicKey>(
    state: JdkCryptographyState,
) : JdkPublicKeyDecoder<RSA.PublicKey.Format, K>(state, "RSA") {
    override fun decodeFromByteArrayBlocking(format: RSA.PublicKey.Format, bytes: ByteArray): K = decodeFromDer(
        when (format) {
            RSA.PublicKey.Format.JWK       -> error("$format is not supported")
            RSA.PublicKey.Format.DER       -> bytes
            RSA.PublicKey.Format.PEM       -> unwrapPem(PemLabel.PublicKey, bytes)
            RSA.PublicKey.Format.DER.PKCS1 -> wrapSubjectPublicKeyInfo(RsaKeyAlgorithmIdentifier, bytes)
            RSA.PublicKey.Format.PEM.PKCS1 -> wrapSubjectPublicKeyInfo(RsaKeyAlgorithmIdentifier, unwrapPem(PemLabel.RsaPublicKey, bytes))
        }
    )
}

internal abstract class RsaPrivateKeyDecoder<K : RSA.PrivateKey>(
    state: JdkCryptographyState,
) : JdkPrivateKeyDecoder<RSA.PrivateKey.Format, K>(state, "RSA") {
    override fun decodeFromByteArrayBlocking(format: RSA.PrivateKey.Format, bytes: ByteArray): K = decodeFromDer(
        when (format) {
            RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
            RSA.PrivateKey.Format.DER       -> bytes
            RSA.PrivateKey.Format.PEM       -> unwrapPem(PemLabel.PrivateKey, bytes)
            RSA.PrivateKey.Format.DER.PKCS1 -> wrapPrivateKeyInfo(0, RsaKeyAlgorithmIdentifier, bytes)
            RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPrivateKeyInfo(0, RsaKeyAlgorithmIdentifier, unwrapPem(PemLabel.RsaPrivateKey, bytes))
        }
    )
}

internal abstract class RsaPublicEncodableKey(
    key: JPublicKey,
) : JdkEncodableKey<RSA.PublicKey.Format>(key) {
    override fun encodeToByteArrayBlocking(format: RSA.PublicKey.Format): ByteArray = when (format) {
        RSA.PublicKey.Format.JWK       -> error("$format is not supported")
        RSA.PublicKey.Format.DER       -> encodeToDer()
        RSA.PublicKey.Format.PEM       -> wrapPem(PemLabel.PublicKey, encodeToDer())
        RSA.PublicKey.Format.DER.PKCS1 -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.RSA, encodeToDer())
        RSA.PublicKey.Format.PEM.PKCS1 -> wrapPem(
            PemLabel.RsaPublicKey,
            unwrapSubjectPublicKeyInfo(ObjectIdentifier.RSA, encodeToDer())
        )
    }
}

internal abstract class RsaPrivateEncodableKey(
    key: JPrivateKey,
) : JdkEncodableKey<RSA.PrivateKey.Format>(key) {
    override fun encodeToByteArrayBlocking(format: RSA.PrivateKey.Format): ByteArray = when (format) {
        RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
        RSA.PrivateKey.Format.DER       -> encodeToDer()
        RSA.PrivateKey.Format.PEM       -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        RSA.PrivateKey.Format.DER.PKCS1 -> unwrapPrivateKeyInfo(ObjectIdentifier.RSA, encodeToDer())
        RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPem(
            PemLabel.RsaPrivateKey,
            unwrapPrivateKeyInfo(ObjectIdentifier.RSA, encodeToDer())
        )
    }
}
