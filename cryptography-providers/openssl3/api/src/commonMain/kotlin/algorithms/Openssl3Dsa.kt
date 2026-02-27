/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Dsa : DSA {

    override fun publicKeyDecoder(): Decoder<DSA.PublicKey.Format, DSA.PublicKey> = DsaPublicKeyDecoder

    override fun privateKeyDecoder(): Decoder<DSA.PrivateKey.Format, DSA.PrivateKey> = DsaPrivateKeyDecoder

    override fun keyPairGenerator(keySize: BinarySize): KeyGenerator<DSA.KeyPair> =
        DsaKeyPairGenerator(pBits = keySize.inBits.toUInt())

    private object DsaPublicKeyDecoder : Openssl3PublicKeyDecoder<DSA.PublicKey.Format, DSA.PublicKey>("DSA") {
        override fun inputType(format: DSA.PublicKey.Format): String = when (format) {
            DSA.PublicKey.Format.DER -> "DER"
            DSA.PublicKey.Format.PEM -> "PEM"
            DSA.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.PublicKey = DsaPublicKey(key)
    }

    private object DsaPrivateKeyDecoder : Openssl3PrivateKeyDecoder<DSA.PrivateKey.Format, DSA.PrivateKey>("DSA") {
        override fun inputType(format: DSA.PrivateKey.Format): String = when (format) {
            DSA.PrivateKey.Format.DER -> "DER"
            DSA.PrivateKey.Format.PEM -> "PEM"
            DSA.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.PrivateKey = DsaPrivateKey(key, publicKey = null)
    }

    private class DsaKeyPairGenerator(
        private val pBits: UInt,
        private val qBits: UInt? = null, // optional; can be set later if needed
    ) : KeyGenerator<DSA.KeyPair> {

        @OptIn(UnsafeNumber::class)
        override fun generateKeyBlocking(): DSA.KeyPair = memScoped {
            // 1) generate DSA parameters
            val paramCtx = checkError(EVP_PKEY_CTX_new_from_name(null, "DSA", null))
            val paramsKey: CPointer<EVP_PKEY> = try {
                checkError(EVP_PKEY_paramgen_init(paramCtx))

                val params = OSSL_PARAM_array(
                    OSSL_PARAM_construct_uint("pbits".cstr.ptr, alloc(pBits).ptr),
                    qBits?.let { OSSL_PARAM_construct_uint("qbits".cstr.ptr, alloc(it).ptr) },
                )
                checkError(EVP_PKEY_CTX_set_params(paramCtx, params))

                val paramsKeyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(paramCtx, paramsKeyVar.ptr))
                checkError(paramsKeyVar.value)
            } finally {
                EVP_PKEY_CTX_free(paramCtx)
            }

            // 2) generate key pair from parameters
            val keyCtx = checkError(EVP_PKEY_CTX_new_from_pkey(null, paramsKey, null))
            try {
                checkError(EVP_PKEY_keygen_init(keyCtx))

                val keyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(keyCtx, keyVar.ptr))
                val keyPairKey = checkError(keyVar.value)

                val publicKey = DsaPublicKey(keyPairKey)
                DsaKeyPair(
                    publicKey = publicKey,
                    privateKey = DsaPrivateKey(keyPairKey, publicKey)
                )
            } finally {
                EVP_PKEY_CTX_free(keyCtx)
                EVP_PKEY_free(paramsKey)
            }
        }
    }

    private class DsaKeyPair(
        override val publicKey: DSA.PublicKey,
        override val privateKey: DSA.PrivateKey,
    ) : DSA.KeyPair

    private class DsaPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : DSA.PublicKey, Openssl3PublicKeyEncodable<DSA.PublicKey.Format>(key) {

        override fun outputType(format: DSA.PublicKey.Format): String = when (format) {
            DSA.PublicKey.Format.DER -> "DER"
            DSA.PublicKey.Format.PEM -> "PEM"
            DSA.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>?, format: DSA.SignatureFormat): SignatureVerifier {
            checkNotNull(digest) { "Pre-hashed (digest=null) DSA is not supported" }

            val derVerifier = DsaDigestSignatureVerifier(key, hashAlgorithmName(digest))

            return when (format) {
                DSA.SignatureFormat.DER -> derVerifier
                DSA.SignatureFormat.RAW -> error("$format is not supported")
            }
        }
    }

    private class DsaPrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: DSA.PublicKey?,
    ) : DSA.PrivateKey,
        Openssl3PrivateKeyEncodable<DSA.PrivateKey.Format, DSA.PublicKey>(key, publicKey) {

        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): DSA.PublicKey = DsaPublicKey(key)

        override fun outputType(format: DSA.PrivateKey.Format): String = when (format) {
            DSA.PrivateKey.Format.DER -> "DER"
            DSA.PrivateKey.Format.PEM -> "PEM"
            DSA.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>?, format: DSA.SignatureFormat): SignatureGenerator {
            checkNotNull(digest) { "Pre-hashed (digest=null) DSA is not supported" }

            val derGenerator = DsaDigestSignatureGenerator(key, hashAlgorithmName(digest))

            return when (format) {
                DSA.SignatureFormat.DER -> derGenerator
                DSA.SignatureFormat.RAW -> error("$format is not supported")
            }
        }
    }
}

private class DsaDigestSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class DsaDigestSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}
