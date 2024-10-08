/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*

internal abstract class Openssl3Rsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> :
    RSA<PublicK, PrivateK, KP> {

    protected abstract fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): KP
    protected abstract fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): PublicK
    protected abstract fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): PrivateK

    final override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, PublicK> =
        RsaPublicKeyDecoder(hashAlgorithm(digest))

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

        override fun wrapKey(key: CPointer<EVP_PKEY>): PublicK = wrapPublicKey(hashAlgorithm, key)
    }

    final override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, PrivateK> =
        RsaPrivateKeyDecoder(hashAlgorithm(digest))

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

        override fun wrapKey(key: CPointer<EVP_PKEY>): PrivateK = wrapPrivateKey(hashAlgorithm, key)
    }

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> = RsaKeyGenerator(
        keySizeBits = keySize.inBits.toUInt(),
        hashAlgorithm = hashAlgorithm(digest),
        publicExponent = publicExponent.toUInt(),
    )

    private inner class RsaKeyGenerator(
        private val keySizeBits: UInt,
        private val hashAlgorithm: String,
        private val publicExponent: UInt,
    ) : Openssl3KeyPairGenerator<KP>("RSA") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
            OSSL_PARAM_construct_uint("bits".cstr.ptr, alloc(keySizeBits).ptr),
            OSSL_PARAM_construct_uint("e".cstr.ptr, alloc(publicExponent).ptr)
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): KP = wrapKeyPair(hashAlgorithm, keyPair)
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

    protected abstract class RsaPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : RSA.PrivateKey, Openssl3PrivateKeyEncodable<RSA.PrivateKey.Format>(key) {
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
