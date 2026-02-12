/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*

internal abstract class Openssl3Rsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey<PublicK>, KP : RSA.KeyPair<PublicK, PrivateK>>(
    private val wrapPublicKey: (CPointer<EVP_PKEY>, String) -> PublicK,
    private val wrapPrivateKey: (CPointer<EVP_PKEY>, String, PublicK?) -> PrivateK,
    private val wrapKeyPair: (PublicK, PrivateK) -> KP,
) : RSA<PublicK, PrivateK, KP> {

    final override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PublicKey.Format, PublicK> =
        RsaPublicKeyDecoder(hashAlgorithmName(digest))

    private inner class RsaPublicKeyDecoder(
        private val hashAlgorithm: String,
    ) : Openssl3PublicKeyDecoder<RSA.PublicKey.Format, PublicK>("RSA") {
        override fun inputType(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER, RSA.PublicKey.Format.DER.PKCS1 -> "DER"
            RSA.PublicKey.Format.PEM, RSA.PublicKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun inputStruct(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER.PKCS1, RSA.PublicKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.inputStruct(format)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): PublicK = wrapPublicKey(key, hashAlgorithm)
    }

    final override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PrivateKey.Format, PrivateK> =
        RsaPrivateKeyDecoder(hashAlgorithmName(digest))

    private inner class RsaPrivateKeyDecoder(
        private val hashAlgorithm: String,
    ) : Openssl3PrivateKeyDecoder<RSA.PrivateKey.Format, PrivateK>("RSA") {
        override fun inputType(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.DER.PKCS1 -> "DER"
            RSA.PrivateKey.Format.PEM, RSA.PrivateKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun inputStruct(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER.PKCS1, RSA.PrivateKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.inputStruct(format)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): PrivateK = wrapPrivateKey(key, hashAlgorithm, null)
    }

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> = RsaKeyGenerator(
        keySizeBits = keySize.inBits.toUInt(),
        hashAlgorithm = hashAlgorithmName(digest),
        publicExponent = publicExponent.toUInt(),
    )

    private inner class RsaKeyGenerator(
        private val keySizeBits: UInt,
        private val hashAlgorithm: String,
        private val publicExponent: UInt,
    ) : Openssl3KeyPairGenerator<KP>("RSA") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
            OSSL_PARAM_construct_uint("bits".cstr.ptr, alloc(keySizeBits).ptr),
            OSSL_PARAM_construct_uint("e".cstr.ptr, alloc(publicExponent).ptr)
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): KP {
            val publicKey = wrapPublicKey(keyPair, hashAlgorithm)
            val privateKey = wrapPrivateKey(keyPair, hashAlgorithm, publicKey)
            return wrapKeyPair(publicKey, privateKey)
        }
    }

    protected abstract class RsaPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : RSA.PublicKey, Openssl3PublicKeyEncodable<RSA.PublicKey.Format>(key) {
        override fun outputType(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER, RSA.PublicKey.Format.DER.PKCS1 -> "DER"
            RSA.PublicKey.Format.PEM, RSA.PublicKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun outputStruct(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER.PKCS1, RSA.PublicKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.outputStruct(format)
        }
    }

    protected abstract inner class RsaPrivateKey(
        key: CPointer<EVP_PKEY>,
        protected val hashAlgorithm: String,
        publicKey: PublicK?,
    ) : RSA.PrivateKey<PublicK>, Openssl3PrivateKeyEncodable<RSA.PrivateKey.Format, PublicK>(key, publicKey) {
        final override fun wrapPublicKey(key: CPointer<EVP_PKEY>): PublicK = wrapPublicKey(key, hashAlgorithm)

        override fun outputType(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.DER.PKCS1 -> "DER"
            RSA.PrivateKey.Format.PEM, RSA.PrivateKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun outputStruct(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER.PKCS1, RSA.PrivateKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.outputStruct(format)
        }
    }
}
