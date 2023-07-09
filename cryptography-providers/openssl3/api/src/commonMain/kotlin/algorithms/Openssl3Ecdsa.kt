/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import kotlinx.cinterop.*
import platform.posix.*

internal object Openssl3Ecdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> = EcPublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> = EcPrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> = EcKeyGenerator(curve)

    private class EcPrivateKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PrivateKeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey>("EC") {
        override fun inputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER -> "DER"
            EC.PrivateKey.Format.PEM -> "PEM"
            EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDSA.PrivateKey {
            EC_check_key_group(key, curve)
            return EcPrivateKey(key)
        }
    }

    private class EcPublicKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PublicKeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey>("EC") {
        override fun inputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW -> error("should not be called")
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun decodeFromBlocking(format: EC.PublicKey.Format, input: ByteArray): ECDSA.PublicKey = when (format) {
            EC.PublicKey.Format.RAW -> memScoped {
                val context = checkError(EVP_PKEY_CTX_new_from_name(null, "EC", null))
                try {
                    checkError(EVP_PKEY_fromdata_init(context))
                    val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
                    checkError(
                        EVP_PKEY_fromdata(
                            ctx = context,
                            ppkey = pkeyVar.ptr,
                            selection = EVP_PKEY_PUBLIC_KEY,
                            param = OSSL_PARAM_array(
                                OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0U),
                                OSSL_PARAM_construct_octet_string("pub".cstr.ptr, input.safeRefToU(0), input.size.convert())
                            )
                        )
                    )
                    val pkey = checkError(pkeyVar.value)
                    wrapKey(pkey)
                } finally {
                    EVP_PKEY_CTX_free(context)
                }
            }
            else                    -> super.decodeFromBlocking(format, input)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDSA.PublicKey {
            EC_check_key_group(key, curve)
            return EcPublicKey(key)
        }
    }

    private class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : Openssl3KeyPairGenerator<ECDSA.KeyPair>("EC") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
            OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0U)
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): ECDSA.KeyPair = EcKeyPair(
            publicKey = EcPublicKey(keyPair),
            privateKey = EcPrivateKey(keyPair)
        )
    }

    private class EcKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDSA.PrivateKey, Openssl3PrivateKeyEncodable<EC.PrivateKey.Format>(key) {
        override fun outputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER -> "DER"
            EC.PrivateKey.Format.PEM -> "PEM"
            EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
            val derSignatureGenerator = EcdsaDerSignatureGenerator(key, hashAlgorithm(digest))
            return when (format) {
                ECDSA.SignatureFormat.DER -> derSignatureGenerator
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(EC_order_size(key), derSignatureGenerator)
            }
        }
    }

    private class EcPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDSA.PublicKey, Openssl3PublicKeyEncodable<EC.PublicKey.Format>(key) {
        override fun outputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW -> error("should not be called")
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
            EC.PublicKey.Format.RAW -> memScoped {
                val outVar = alloc<size_tVar>()
                checkError(EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", null, 0U, outVar.ptr))
                val output = ByteArray(outVar.value.convert())
                checkError(EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", output.safeRefToU(0), output.size.convert(), outVar.ptr))
                output.ensureSizeExactly(outVar.value.convert())
            }
            else                    -> super.encodeToBlocking(format)
        }

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
            val derSignatureVerifier = EcdsaDerSignatureVerifier(key, hashAlgorithm(digest))
            return when (format) {
                ECDSA.SignatureFormat.DER -> derSignatureVerifier
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(EC_order_size(key), derSignatureVerifier)
            }
        }
    }
}

private fun EC_check_key_group(key: CPointer<EVP_PKEY>, expectedCurve: EC.Curve) = memScoped {
    //we need to construct a group, because our EC.Curve names are not the ones, which are used inside openssl
    val expectedGroup = checkError(
        EC_GROUP_new_from_params(
            OSSL_PARAM_array(
                OSSL_PARAM_construct_utf8_string("group".cstr.ptr, expectedCurve.name.cstr.ptr, 0U)
            ), null, null
        )
    )
    try {
        val expectedGroupNid = checkError(EC_GROUP_get_curve_name(expectedGroup))
        val expectedGroupName = checkError(OSSL_EC_curve_nid2name(expectedGroupNid)).toKString()

        val keyGroupName = allocArray<ByteVar>(256).also {
            checkError(EVP_PKEY_get_utf8_string_param(key, "group", it, 256U, null))
        }.toKString()

        check(expectedGroupName == keyGroupName) {
            "Wrong curve, expected ${expectedCurve.name}($expectedGroupName) actual $keyGroupName"
        }
    } finally {
        EC_GROUP_free(expectedGroup)
    }
}

private fun EC_order_size(key: CPointer<EVP_PKEY>): Int = memScoped {
    val orderVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "order", orderVar.ptr))
    val order = checkError(orderVar.value)
    try {
        return (checkError(BN_num_bits(order)) + 7) / 8
    } finally {
        BN_free(order)
    }
}

private class EcdsaDerSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaRawSignatureGenerator(
    private val orderSizeBytes: Int,
    private val derSignatureGenerator: EcdsaDerSignatureGenerator,
) : SignatureGenerator {
    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray {
        val derSignature = derSignatureGenerator.generateSignatureBlocking(dataInput)

        return memScoped {
            val pdataVar = alloc<CPointerVar<UByteVar>> { value = allocArrayOf(derSignature).reinterpret() }
            val sig = checkError(d2i_ECDSA_SIG(null, pdataVar.ptr, derSignature.size.convert()))
            try {
                val r = checkError(ECDSA_SIG_get0_r(sig))
                val s = checkError(ECDSA_SIG_get0_s(sig))
                val signature = ByteArray(orderSizeBytes * 2)
                checkError(BN_bn2binpad(r, signature.refToU(0), orderSizeBytes))
                checkError(BN_bn2binpad(s, signature.refToU(orderSizeBytes), orderSizeBytes))
                signature
            } finally {
                ECDSA_SIG_free(sig)
            }
        }
    }
}

private class EcdsaDerSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaRawSignatureVerifier(
    private val orderSizeBytes: Int,
    private val derSignatureVerifier: EcdsaDerSignatureVerifier,
) : SignatureVerifier {
    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        if (signatureInput.size != orderSizeBytes * 2) return false

        return memScoped {
            val r = BN_bin2bn(signatureInput.refToU(0), orderSizeBytes, null)
            val s = BN_bin2bn(signatureInput.refToU(orderSizeBytes), orderSizeBytes, null)
            val sig = ECDSA_SIG_new()
            try {
                checkError(ECDSA_SIG_set0(sig, r, s))
                val outVar = alloc<CPointerVar<UByteVar>>()
                val signatureLength = checkError(i2d_ECDSA_SIG(sig, outVar.ptr))
                val derSignature = outVar.value!!.readBytes(signatureLength)
                derSignatureVerifier.verifySignatureBlocking(dataInput, derSignature)
            } finally {
                ECDSA_SIG_free(sig)
            }
        }
    }
}
