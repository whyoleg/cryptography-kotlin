/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*
import dev.whyoleg.cryptography.serialization.asn1.modules.RsaPrivateKey as Asn1RsaPrivateKey
import dev.whyoleg.cryptography.serialization.asn1.modules.RsaPublicKey as Asn1RsaPublicKey

internal abstract class SecRsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey<PublicK>, KP : RSA.KeyPair<PublicK, PrivateK>>(
    private val wrapPublicKey: (SecKeyRef, CryptographyAlgorithmId<Digest>) -> PublicK,
    private val wrapPrivateKey: (SecKeyRef, CryptographyAlgorithmId<Digest>, PublicK?) -> PrivateK,
    private val wrapKeyPair: (PublicK, PrivateK) -> KP,
) : RSA<PublicK, PrivateK, KP> {

    protected abstract fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm?

    final override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PublicKey.Format, PublicK> =
        RsaPublicKeyDecoder(digest)

    private inner class RsaPublicKeyDecoder(
        private val digest: CryptographyAlgorithmId<Digest>,
    ) : Decoder<RSA.PublicKey.Format, PublicK> {

        override fun decodeFromByteArrayBlocking(format: RSA.PublicKey.Format, bytes: ByteArray): PublicK {
            val pkcs1DerKey = when (format) {
                RSA.PublicKey.Format.JWK -> {
                    val components = JsonWebKeys.decodeRsaPublicKey(this@SecRsa.id, digest, bytes)
                    Der.encodeToByteArray(
                        Asn1RsaPublicKey.serializer(),
                        Asn1RsaPublicKey(
                            modulus = BigInt.fromMagnitude(sign = 1, components.n),
                            publicExponent = BigInt.fromMagnitude(sign = 1, components.e),
                        )
                    )
                }
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

            return wrapPublicKey(secKey, digest)
        }
    }

    final override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PrivateKey.Format, PrivateK> =
        RsaPrivateKeyDecoder(digest)

    private inner class RsaPrivateKeyDecoder(
        private val digest: CryptographyAlgorithmId<Digest>,
    ) : Decoder<RSA.PrivateKey.Format, PrivateK> {

        override fun decodeFromByteArrayBlocking(format: RSA.PrivateKey.Format, bytes: ByteArray): PrivateK {
            val pkcs1DerKey = when (format) {
                RSA.PrivateKey.Format.JWK -> {
                    val components = JsonWebKeys.decodeRsaPrivateKey(this@SecRsa.id, digest, bytes)
                    Der.encodeToByteArray(
                        Asn1RsaPrivateKey.serializer(),
                        Asn1RsaPrivateKey(
                            version = 0,
                            modulus = BigInt.fromMagnitude(sign = 1, components.n),
                            publicExponent = BigInt.fromMagnitude(sign = 1, components.e),
                            privateExponent = BigInt.fromMagnitude(sign = 1, components.d),
                            prime1 = BigInt.fromMagnitude(sign = 1, components.p),
                            prime2 = BigInt.fromMagnitude(sign = 1, components.q),
                            exponent1 = BigInt.fromMagnitude(sign = 1, components.dp),
                            exponent2 = BigInt.fromMagnitude(sign = 1, components.dq),
                            coefficient = BigInt.fromMagnitude(sign = 1, components.qi),
                        )
                    )
                }
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

            return wrapPrivateKey(secKey, digest, null)
        }
    }

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> {
        check(publicExponent == 65537.toBigInt()) { "Only F4(default) public exponent is supported" }

        return RsaKeyGenerator(keySize.inBits, digest)
    }

    private inner class RsaKeyGenerator(
        private val keySizeBits: Int,
        private val digest: CryptographyAlgorithmId<Digest>,
    ) : KeyGenerator<KP> {
        override fun generateKeyBlocking(): KP {
            val secPrivateKey = CFMutableDictionary(2) {
                add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
                @Suppress("CAST_NEVER_SUCCEEDS")
                add(kSecAttrKeySizeInBits, (keySizeBits as NSNumber).retainBridge())
            }.use { attributes ->
                generateSecKey(attributes)
            }

            val publicKey = wrapPublicKey(SecKeyCopyPublicKey(secPrivateKey)!!, digest)
            val privateKey = wrapPrivateKey(secPrivateKey, digest, publicKey)
            return wrapKeyPair(publicKey, privateKey)
        }
    }

    protected abstract inner class RsaPublicKey(
        protected val publicKey: SecKeyRef,
        protected val digest: CryptographyAlgorithmId<Digest>,
    ) : RSA.PublicKey {

        @OptIn(ExperimentalNativeApi::class)
        private val cleanup = createCleaner(publicKey, SecKeyRef::release)

        final override fun encodeToByteArrayBlocking(format: RSA.PublicKey.Format): ByteArray {
            val pkcs1Key = exportSecKey(publicKey)

            return when (format) {
                RSA.PublicKey.Format.JWK -> {
                    val rsaPubKey = Der.decodeFromByteArray(Asn1RsaPublicKey.serializer(), pkcs1Key)
                    JsonWebKeys.encodeRsaPublicKey(
                        algorithmId = this@SecRsa.id,
                        digest = digest,
                        n = rsaPubKey.modulus.magnitudeToByteArray(),
                        e = rsaPubKey.publicExponent.magnitudeToByteArray(),
                    )
                }
                RSA.PublicKey.Format.DER.PKCS1 -> pkcs1Key
                RSA.PublicKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPublicKey, pkcs1Key)
                RSA.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(RsaAlgorithmIdentifier, pkcs1Key)
                RSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, wrapSubjectPublicKeyInfo(RsaAlgorithmIdentifier, pkcs1Key))
            }
        }
    }

    protected abstract inner class RsaPrivateKey(
        protected val privateKey: SecKeyRef,
        protected val digest: CryptographyAlgorithmId<Digest>,
        private var publicKey: PublicK?,
    ) : RSA.PrivateKey<PublicK> {

        @OptIn(ExperimentalNativeApi::class)
        private val cleanup = createCleaner(privateKey, SecKeyRef::release)

        final override fun getPublicKeyBlocking(): PublicK {
            if (publicKey == null) {
                publicKey = wrapPublicKey(SecKeyCopyPublicKey(privateKey)!!, digest)
            }
            return publicKey!!
        }

        final override fun encodeToByteArrayBlocking(format: RSA.PrivateKey.Format): ByteArray {
            val pkcs1Key = exportSecKey(privateKey)

            return when (format) {
                RSA.PrivateKey.Format.JWK -> {
                    val rsaPrivKey = Der.decodeFromByteArray(Asn1RsaPrivateKey.serializer(), pkcs1Key)
                    JsonWebKeys.encodeRsaPrivateKey(
                        algorithmId = this@SecRsa.id,
                        digest = digest,
                        n = rsaPrivKey.modulus.magnitudeToByteArray(),
                        e = rsaPrivKey.publicExponent.magnitudeToByteArray(),
                        d = rsaPrivKey.privateExponent.magnitudeToByteArray(),
                        p = rsaPrivKey.prime1.magnitudeToByteArray(),
                        q = rsaPrivKey.prime2.magnitudeToByteArray(),
                        dp = rsaPrivKey.exponent1.magnitudeToByteArray(),
                        dq = rsaPrivKey.exponent2.magnitudeToByteArray(),
                        qi = rsaPrivKey.coefficient.magnitudeToByteArray(),
                    )
                }
                RSA.PrivateKey.Format.DER.PKCS1 -> pkcs1Key
                RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPrivateKey, pkcs1Key)
                RSA.PrivateKey.Format.DER -> wrapPrivateKeyInfo(0, RsaAlgorithmIdentifier, pkcs1Key)
                RSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, wrapPrivateKeyInfo(0, RsaAlgorithmIdentifier, pkcs1Key))
            }
        }
    }
}
