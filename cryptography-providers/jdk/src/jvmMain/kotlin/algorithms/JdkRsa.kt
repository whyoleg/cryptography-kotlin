/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.security.interfaces.*
import java.security.spec.*

internal sealed class JdkRsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey<PublicK>, KP : RSA.KeyPair<PublicK, PrivateK>>(
    protected val state: JdkCryptographyState,
) : RSA<PublicK, PrivateK, KP> {
    protected abstract val wrapPublicKey: (JPublicKey, String) -> PublicK
    protected abstract val wrapPrivateKey: (JPrivateKey, String, PublicK?) -> PrivateK
    protected abstract val wrapKeyPair: (PublicK, PrivateK) -> KP

    //rsa JDK uses slightly different names for hash algorithms
    protected open fun hashAlgorithmName(digest: CryptographyAlgorithmId<Digest>): String = when (digest) {
        SHA1     -> "SHA-1"
        SHA224   -> "SHA-224"
        SHA256   -> "SHA-256"
        SHA384   -> "SHA-384"
        SHA512   -> "SHA-512"
        SHA3_224 -> "SHA3-224"
        SHA3_256 -> "SHA3-256"
        SHA3_384 -> "SHA3-384"
        SHA3_512 -> "SHA3-512"
        else -> throw IllegalStateException("Unsupported hash algorithm: $digest")
    }

    final override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PrivateKey.Format, PrivateK> {
        return RsaPrivateKeyDecoder(hashAlgorithmName(digest))
    }

    final override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PublicKey.Format, PublicK> {
        return RsaPublicKeyDecoder(hashAlgorithmName(digest))
    }

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.inBits,
            publicExponent.toJavaBigInteger(),
        )
        return RsaKeyPairGenerator(rsaParameters, hashAlgorithmName(digest))
    }

    private inner class RsaPublicKeyDecoder(
        private val hashAlgorithmName: String,
    ) : JdkPublicKeyDecoder<RSA.PublicKey.Format, PublicK>(state, "RSA") {
        override fun JPublicKey.convert(): PublicK = wrapPublicKey(this, hashAlgorithmName)

        fun fromPrivateKey(privateKey: RSAPrivateCrtKey): PublicK = decode(RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent))

        override fun decodeFromByteArrayBlocking(format: RSA.PublicKey.Format, bytes: ByteArray): PublicK = decodeFromDer(
            when (format) {
                RSA.PublicKey.Format.JWK       -> error("$format is not supported")
                RSA.PublicKey.Format.DER       -> bytes
                RSA.PublicKey.Format.PEM       -> unwrapPem(PemLabel.PublicKey, bytes)
                RSA.PublicKey.Format.DER.PKCS1 -> wrapSubjectPublicKeyInfo(RsaAlgorithmIdentifier, bytes)
                RSA.PublicKey.Format.PEM.PKCS1 -> wrapSubjectPublicKeyInfo(
                    RsaAlgorithmIdentifier,
                    unwrapPem(PemLabel.RsaPublicKey, bytes)
                )
            }
        )
    }

    private inner class RsaPrivateKeyDecoder(
        private val hashAlgorithmName: String,
    ) : JdkPrivateKeyDecoder<RSA.PrivateKey.Format, PrivateK>(state, "RSA") {
        override fun JPrivateKey.convert(): PrivateK = wrapPrivateKey(this, hashAlgorithmName, null)

        override fun decodeFromByteArrayBlocking(format: RSA.PrivateKey.Format, bytes: ByteArray): PrivateK = decodeFromDer(
            when (format) {
                RSA.PrivateKey.Format.JWK       -> error("$format is not supported")
                RSA.PrivateKey.Format.DER       -> bytes
                RSA.PrivateKey.Format.PEM       -> unwrapPem(PemLabel.PrivateKey, bytes)
                RSA.PrivateKey.Format.DER.PKCS1 -> wrapPrivateKeyInfo(0, RsaAlgorithmIdentifier, bytes)
                RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPrivateKeyInfo(
                    0,
                    RsaAlgorithmIdentifier,
                    unwrapPem(PemLabel.RsaPrivateKey, bytes)
                )
            }
        )
    }

    private inner class RsaKeyPairGenerator(
        private val keyGenParameters: RSAKeyGenParameterSpec,
        private val hashAlgorithmName: String,
    ) : JdkKeyPairGenerator<KP>(state, "RSA") {
        override fun JKeyPairGenerator.init() {
            initialize(keyGenParameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): KP {
            val publicKey = wrapPublicKey(public, hashAlgorithmName)
            val privateKey = wrapPrivateKey(private, hashAlgorithmName, publicKey)
            return wrapKeyPair(publicKey, privateKey)
        }
    }

    protected abstract class RsaPublicEncodableKey(
        protected val key: JPublicKey,
    ) : JdkEncodableKey<RSA.PublicKey.Format>(key) {
        final override fun encodeToByteArrayBlocking(format: RSA.PublicKey.Format): ByteArray = when (format) {
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

    protected abstract inner class RsaPrivateEncodableKey(
        protected val key: JPrivateKey,
        protected val hashAlgorithmName: String,
        private var publicKey: PublicK?,
    ) : JdkEncodableKey<RSA.PrivateKey.Format>(key), RSA.PrivateKey<PublicK> {
        final override fun getPublicKeyBlocking(): PublicK {
            if (publicKey == null) {
                publicKey = RsaPublicKeyDecoder(hashAlgorithmName).fromPrivateKey(key as RSAPrivateCrtKey)
            }
            return publicKey!!
        }

        final override fun encodeToByteArrayBlocking(format: RSA.PrivateKey.Format): ByteArray = when (format) {
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
}
