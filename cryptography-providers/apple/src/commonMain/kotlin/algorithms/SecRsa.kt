/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal abstract class SecRsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> :
    RSA<PublicK, PrivateK, KP> {

    protected abstract fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm?

    protected abstract fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): KP
    protected abstract fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): PublicK
    protected abstract fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): PrivateK

    final override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, PublicK> =
        RsaPublicKeyDecoder(hashAlgorithm(digest))

    private inner class RsaPublicKeyDecoder(private val algorithm: SecKeyAlgorithm?) : KeyDecoder<RSA.PublicKey.Format, PublicK> {

        override fun decodeFromByteArrayBlocking(format: RSA.PublicKey.Format, bytes: ByteArray): PublicK {
            val pkcs1DerKey = when (format) {
                RSA.PublicKey.Format.JWK -> error("$format is not supported")
                RSA.PublicKey.Format.DER.PKCS1 -> bytes
                RSA.PublicKey.Format.PEM.PKCS1 -> unwrapPem(PemLabel.RsaPublicKey, bytes)
                RSA.PublicKey.Format.DER -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.RSA, bytes)
                RSA.PublicKey.Format.PEM -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.RSA, unwrapPem(PemLabel.PublicKey, bytes))
            }

            val secKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                add(kSecAttrKeyClass, kSecAttrKeyClassPublic)
            }.use { attributes ->
                decodeSecKey(pkcs1DerKey, attributes)
            }

            return wrapPublicKey(algorithm, secKey)
        }
    }

    final override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, PrivateK> =
        RsaPrivateKeyDecoder(hashAlgorithm(digest))

    private inner class RsaPrivateKeyDecoder(private val algorithm: SecKeyAlgorithm?) : KeyDecoder<RSA.PrivateKey.Format, PrivateK> {

        override fun decodeFromByteArrayBlocking(format: RSA.PrivateKey.Format, bytes: ByteArray): PrivateK {
            val pkcs1DerKey = when (format) {
                RSA.PrivateKey.Format.JWK -> error("$format is not supported")
                RSA.PrivateKey.Format.DER.PKCS1 -> bytes
                RSA.PrivateKey.Format.PEM.PKCS1 -> unwrapPem(PemLabel.RsaPrivateKey, bytes)
                RSA.PrivateKey.Format.DER -> unwrapPrivateKeyInfo(ObjectIdentifier.RSA, bytes)
                RSA.PrivateKey.Format.PEM -> unwrapPrivateKeyInfo(ObjectIdentifier.RSA, unwrapPem(PemLabel.PrivateKey, bytes))
            }

            val secKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                add(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            }.use { attributes ->
                decodeSecKey(pkcs1DerKey, attributes)
            }

            return wrapPrivateKey(algorithm, secKey)
        }
    }

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> {
        check(publicExponent == 65537.toBigInt()) { "Only F4(default) public exponent is supported" }

        return RsaKeyGenerator(keySize.inBits, hashAlgorithm(digest))
    }

    private inner class RsaKeyGenerator(
        private val keySizeBits: Int,
        private val algorithm: SecKeyAlgorithm?,
    ) : KeyGenerator<KP> {
        override fun generateKeyBlocking(): KP {
            val privateKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                @Suppress("CAST_NEVER_SUCCEEDS")
                add(kSecAttrKeySizeInBits, (keySizeBits as NSNumber).retainBridge())
            }.use { attributes ->
                generateSecKey(attributes)
            }

            val publicKey = SecKeyCopyPublicKey(privateKey)!!
            return wrapKeyPair(algorithm, publicKey, privateKey)
        }
    }

    protected abstract class RsaPublicKey(
        protected val publicKey: SecKeyRef,
    ) : RSA.PublicKey {
        @OptIn(ExperimentalNativeApi::class)
        private val cleanup = createCleaner(publicKey, SecKeyRef::release)

        final override fun encodeToByteArrayBlocking(format: RSA.PublicKey.Format): ByteArray {
            val pkcs1Key = exportSecKey(publicKey)

            return when (format) {
                RSA.PublicKey.Format.JWK -> error("$format is not supported")
                RSA.PublicKey.Format.DER.PKCS1 -> pkcs1Key
                RSA.PublicKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPublicKey, pkcs1Key)
                RSA.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(RsaKeyAlgorithmIdentifier, pkcs1Key)
                RSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, wrapSubjectPublicKeyInfo(RsaKeyAlgorithmIdentifier, pkcs1Key))
            }
        }
    }

    protected abstract class RsaPrivateKey(
        protected val privateKey: SecKeyRef,
    ) : RSA.PrivateKey {
        @OptIn(ExperimentalNativeApi::class)
        private val cleanup = createCleaner(privateKey, SecKeyRef::release)

        final override fun encodeToByteArrayBlocking(format: RSA.PrivateKey.Format): ByteArray {
            val pkcs1Key = exportSecKey(privateKey)

            return when (format) {
                RSA.PrivateKey.Format.JWK -> error("$format is not supported")
                RSA.PrivateKey.Format.DER.PKCS1 -> pkcs1Key
                RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPrivateKey, pkcs1Key)
                RSA.PrivateKey.Format.DER -> wrapPrivateKeyInfo(0, RsaKeyAlgorithmIdentifier, pkcs1Key)
                RSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, wrapPrivateKeyInfo(0, RsaKeyAlgorithmIdentifier, pkcs1Key))
            }
        }
    }
}
