/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Dsa : DSA {

    override fun publicKeyDecoder(): Decoder<DSA.PublicKey.Format, DSA.PublicKey> = DsaPublicKeyDecoder

    override fun privateKeyDecoder(): Decoder<DSA.PrivateKey.Format, DSA.PrivateKey> = DsaPrivateKeyDecoder

    override fun parametersDecoder(): Decoder<DSA.Parameters.Format, DSA.Parameters> = DsaParametersDecoder

    override fun parametersGenerator(primeSize: BinarySize, subprimeSize: BinarySize?): ParametersGenerator<DSA.Parameters> {
        // by default, openssl uses 224 in case qbits is not provided
        // FIPS 186-2: (1024, 160)
        // FIPS 186-4: (2048, 224), (2048, 256), (3072, 256)
        val subprimeSize = subprimeSize ?: when (primeSize) {
            1024.bits -> 160.bits
            2048.bits -> 224.bits
            3072.bits -> 256.bits
            else      -> throw IllegalArgumentException("Can't infer subprimeSize for primeSize($primeSize), provide it explicitly")
        }
        return DsaParametersGenerator(primeSize.inBits.toUInt(), subprimeSize.inBits.toUInt())
    }

    private object DsaPublicKeyDecoder : Openssl3PublicKeyDecoder<DSA.PublicKey.Format, DSA.PublicKey>("DSA") {
        override fun inputType(format: DSA.PublicKey.Format): String = when (format) {
            DSA.PublicKey.Format.DER -> "DER"
            DSA.PublicKey.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.PublicKey = DsaPublicKey(key)
    }

    private object DsaPrivateKeyDecoder : Openssl3PrivateKeyDecoder<DSA.PrivateKey.Format, DSA.PrivateKey>("DSA") {
        override fun inputType(format: DSA.PrivateKey.Format): String = when (format) {
            DSA.PrivateKey.Format.DER -> "DER"
            DSA.PrivateKey.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.PrivateKey = DsaPrivateKey(key, publicKey = null)
    }

    private object DsaParametersDecoder : Openssl3ParametersDecoder<DSA.Parameters.Format, DSA.Parameters>("DSA") {
        override fun inputType(format: DSA.Parameters.Format): String = when (format) {
            DSA.Parameters.Format.DER -> "DER"
            DSA.Parameters.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.Parameters = Openssl3DsaParameters(key)
    }

    private class DsaParametersGenerator(
        private val pBits: UInt,
        private val qBits: UInt,
    ) : Openssl3ParametersGenerator<DSA.Parameters>("DSA") {
        override fun wrapParameters(key: CPointer<EVP_PKEY>): DSA.Parameters = Openssl3DsaParameters(key)

        @OptIn(UnsafeNumber::class)
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
            OSSL_PARAM_construct_uint("pbits".cstr.ptr, alloc(pBits).ptr),
            OSSL_PARAM_construct_uint("qbits".cstr.ptr, alloc(qBits).ptr),
        )
    }

    private class Openssl3DsaParameters(
        key: CPointer<EVP_PKEY>,
    ) : DSA.Parameters, Openssl3ParametersEncodable<DSA.Parameters.Format>(key) {
        override fun keyPairGenerator(): KeyGenerator<DSA.KeyPair> = DsaKeyPairGenerator(key)

        override fun outputType(format: DSA.Parameters.Format): String = when (format) {
            DSA.Parameters.Format.DER -> "DER"
            DSA.Parameters.Format.PEM -> "PEM"
        }
    }

    private class DsaKeyPairGenerator(key: CPointer<EVP_PKEY>) : Openssl3KeyPairGenerator<DSA.KeyPair>(key) {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): DSA.KeyPair {
            val publicKey = DsaPublicKey(keyPair)
            return DsaKeyPair(
                publicKey = publicKey,
                privateKey = DsaPrivateKey(keyPair, publicKey)
            )
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
        }

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>?, format: DSA.SignatureFormat): SignatureVerifier {
            val derVerifier = when (digest) {
                null -> DsaPhSignatureVerifier(key)
                else -> DsaDigestSignatureVerifier(key, hashAlgorithmName(digest))
            }

            return when (format) {
                DSA.SignatureFormat.DER -> derVerifier
                DSA.SignatureFormat.RAW -> DssRawSignatureVerifier(derVerifier, DSA_q_size(key))
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
        }

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>?, format: DSA.SignatureFormat): SignatureGenerator {
            val derGenerator = when (digest) {
                null -> DsaPhSignatureGenerator(key)
                else -> DsaDigestSignatureGenerator(key, hashAlgorithmName(digest))
            }

            return when (format) {
                DSA.SignatureFormat.DER -> derGenerator
                DSA.SignatureFormat.RAW -> DssRawSignatureGenerator(derGenerator, DSA_q_size(key))
            }
        }
    }
}

private class DsaPhSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
) : Openssl3PhSignatureGenerator(privateKey) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class DsaPhSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
) : Openssl3PhSignatureVerifier(publicKey) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
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

@OptIn(UnsafeNumber::class)
private fun DSA_q_size(key: CPointer<EVP_PKEY>): Int = memScoped {
    val qVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "q", qVar.ptr))
    val q = checkError(qVar.value)
    try {
        (checkError(BN_num_bits(q)) + 7) / 8
    } finally {
        BN_free(q)
    }
}
