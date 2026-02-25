/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*

internal abstract class Openssl3Rsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey<PublicK>, KP : RSA.KeyPair<PublicK, PrivateK>>(
    private val wrapPublicKey: (CPointer<EVP_PKEY>, CryptographyAlgorithmId<Digest>) -> PublicK,
    private val wrapPrivateKey: (CPointer<EVP_PKEY>, CryptographyAlgorithmId<Digest>, PublicK?) -> PrivateK,
    private val wrapKeyPair: (PublicK, PrivateK) -> KP,
) : RSA<PublicK, PrivateK, KP> {

    final override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PublicKey.Format, PublicK> =
        RsaPublicKeyDecoder(digest)

    private inner class RsaPublicKeyDecoder(
        private val digest: CryptographyAlgorithmId<Digest>,
    ) : Openssl3PublicKeyDecoder<RSA.PublicKey.Format, PublicK>("RSA") {
        override fun inputType(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER, RSA.PublicKey.Format.DER.PKCS1 -> "DER"
            RSA.PublicKey.Format.PEM, RSA.PublicKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PublicKey.Format.JWK -> error("should not be called: handled explicitly in decodeFromByteArrayBlocking")
        }

        override fun inputStruct(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER.PKCS1, RSA.PublicKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.inputStruct(format)
        }

        @OptIn(UnsafeNumber::class)
        override fun decodeFromByteArrayBlocking(format: RSA.PublicKey.Format, bytes: ByteArray): PublicK = when (format) {
            RSA.PublicKey.Format.JWK -> {
                val components = JsonWebKeys.decodeRsaPublicKey(this@Openssl3Rsa.id, digest, bytes)
                wrapKey(fromParameters {
                    OSSL_PARAM_array(
                        constructRsaBnParam("n", components.n),
                        constructRsaBnParam("e", components.e),
                    )
                })
            }
            else                     -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): PublicK = wrapPublicKey(key, digest)
    }

    final override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<RSA.PrivateKey.Format, PrivateK> =
        RsaPrivateKeyDecoder(digest)

    private inner class RsaPrivateKeyDecoder(
        private val digest: CryptographyAlgorithmId<Digest>,
    ) : Openssl3PrivateKeyDecoder<RSA.PrivateKey.Format, PrivateK>("RSA") {
        override fun inputType(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.DER.PKCS1 -> "DER"
            RSA.PrivateKey.Format.PEM, RSA.PrivateKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PrivateKey.Format.JWK -> error("should not be called: handled explicitly in decodeFromByteArrayBlocking")
        }

        override fun inputStruct(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER.PKCS1, RSA.PrivateKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.inputStruct(format)
        }

        @OptIn(UnsafeNumber::class)
        override fun decodeFromByteArrayBlocking(format: RSA.PrivateKey.Format, bytes: ByteArray): PrivateK = when (format) {
            RSA.PrivateKey.Format.JWK -> {
                val components = JsonWebKeys.decodeRsaPrivateKey(this@Openssl3Rsa.id, digest, bytes)
                wrapKey(fromParameters {
                    OSSL_PARAM_array(
                        constructRsaBnParam("n", components.n),
                        constructRsaBnParam("e", components.e),
                        constructRsaBnParam("d", components.d),
                        constructRsaBnParam("rsa-factor1", components.p),
                        constructRsaBnParam("rsa-factor2", components.q),
                        constructRsaBnParam("rsa-exponent1", components.dp),
                        constructRsaBnParam("rsa-exponent2", components.dq),
                        constructRsaBnParam("rsa-coefficient1", components.qi),
                    )
                })
            }
            else                      -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): PrivateK = wrapPrivateKey(key, digest, null)
    }

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> = RsaKeyGenerator(
        keySizeBits = keySize.inBits.toUInt(),
        digest = digest,
        publicExponent = publicExponent.toUInt(),
    )

    private inner class RsaKeyGenerator(
        private val keySizeBits: UInt,
        private val digest: CryptographyAlgorithmId<Digest>,
        private val publicExponent: UInt,
    ) : Openssl3KeyPairGenerator<KP>("RSA") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
            OSSL_PARAM_construct_uint("bits".cstr.ptr, alloc(keySizeBits).ptr),
            OSSL_PARAM_construct_uint("e".cstr.ptr, alloc(publicExponent).ptr)
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): KP {
            val publicKey = wrapPublicKey(keyPair, digest)
            val privateKey = wrapPrivateKey(keyPair, digest, publicKey)
            return wrapKeyPair(publicKey, privateKey)
        }
    }

    protected abstract inner class RsaPublicKey(
        key: CPointer<EVP_PKEY>,
        protected val digest: CryptographyAlgorithmId<Digest>,
    ) : RSA.PublicKey, Openssl3PublicKeyEncodable<RSA.PublicKey.Format>(key) {

        override fun outputType(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER, RSA.PublicKey.Format.DER.PKCS1 -> "DER"
            RSA.PublicKey.Format.PEM, RSA.PublicKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PublicKey.Format.JWK -> error("should not be called: handled explicitly in encodeToByteArrayBlocking")
        }

        override fun outputStruct(format: RSA.PublicKey.Format): String = when (format) {
            RSA.PublicKey.Format.DER.PKCS1, RSA.PublicKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.outputStruct(format)
        }

        override fun encodeToByteArrayBlocking(format: RSA.PublicKey.Format): ByteArray = when (format) {
            RSA.PublicKey.Format.JWK -> {
                val n = getRsaBnParam(key, "n")
                val e = getRsaBnParam(key, "e")
                JsonWebKeys.encodeRsaPublicKey(algorithmId = this@Openssl3Rsa.id, digest = digest, n = n, e = e)
            }
            else                     -> super.encodeToByteArrayBlocking(format)
        }
    }

    protected abstract inner class RsaPrivateKey(
        key: CPointer<EVP_PKEY>,
        protected val digest: CryptographyAlgorithmId<Digest>,
        publicKey: PublicK?,
    ) : RSA.PrivateKey<PublicK>, Openssl3PrivateKeyEncodable<RSA.PrivateKey.Format, PublicK>(key, publicKey) {

        final override fun wrapPublicKey(key: CPointer<EVP_PKEY>): PublicK = wrapPublicKey(key, digest)

        override fun outputType(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER, RSA.PrivateKey.Format.DER.PKCS1 -> "DER"
            RSA.PrivateKey.Format.PEM, RSA.PrivateKey.Format.PEM.PKCS1 -> "PEM"
            RSA.PrivateKey.Format.JWK -> error("should not be called: handled explicitly in encodeToByteArrayBlocking")
        }

        override fun outputStruct(format: RSA.PrivateKey.Format): String = when (format) {
            RSA.PrivateKey.Format.DER.PKCS1, RSA.PrivateKey.Format.PEM.PKCS1 -> "pkcs1"
            else -> super.outputStruct(format)
        }

        override fun encodeToByteArrayBlocking(format: RSA.PrivateKey.Format): ByteArray = when (format) {
            RSA.PrivateKey.Format.JWK -> {
                val n = getRsaBnParam(key, "n")
                val e = getRsaBnParam(key, "e")
                val d = getRsaBnParam(key, "d")
                val p = getRsaBnParam(key, "rsa-factor1")
                val q = getRsaBnParam(key, "rsa-factor2")
                val dp = getRsaBnParam(key, "rsa-exponent1")
                val dq = getRsaBnParam(key, "rsa-exponent2")
                val qi = getRsaBnParam(key, "rsa-coefficient1")
                JsonWebKeys.encodeRsaPrivateKey(
                    algorithmId = this@Openssl3Rsa.id, digest = digest,
                    n = n, e = e, d = d, p = p, q = q, dp = dp, dq = dq, qi = qi
                )
            }
            else                      -> super.encodeToByteArrayBlocking(format)
        }
    }
}

private fun getRsaBnParam(key: CPointer<EVP_PKEY>, paramName: String): ByteArray = memScoped {
    val bnVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, paramName, bnVar.ptr))
    val bn = checkError(bnVar.value)
    try {
        val size = BN_num_bytes(bn)
        val bytes = ByteArray(size)
        checkError(BN_bn2binpad(bn, bytes.refToU(0), size))
        bytes
    } finally {
        BN_free(bn)
    }
}

@OptIn(UnsafeNumber::class)
private fun MemScope.constructRsaBnParam(
    name: String,
    value: ByteArray,
): CValue<OSSL_PARAM> {
    // `value` is `big-endian` encoded, but `OSSL_PARAM_construct_BN` accepts `platform endian` as it's just an unsigned value
    // so we need to convert it
    val bn = checkError(BN_bin2bn(value.refToU(0), value.size, null))
    try {
        val size = BN_num_bytes(bn)
        val bytes = allocArray<UByteVar>(size)
        checkError(BN_bn2nativepad(bn, bytes, size))
        return OSSL_PARAM_construct_BN(name.cstr.ptr, bytes, size.convert())
    } finally {
        BN_free(bn)
    }
}
