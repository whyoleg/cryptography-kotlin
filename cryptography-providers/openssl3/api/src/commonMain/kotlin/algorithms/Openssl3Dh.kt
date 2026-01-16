/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.DH
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*
import platform.posix.*

internal object Openssl3Dh : DH {
    override fun publicKeyDecoder(): KeyDecoder<DH.PublicKey.Format, DH.PublicKey> =
        DhPublicKeyDecoder()

    override fun privateKeyDecoder(): KeyDecoder<DH.PrivateKey.Format, DH.PrivateKey> =
        DhPrivateKeyDecoder()

    override fun parametersDecoder(): MaterialDecoder<DH.Parameters.Format, DH.Parameters> =
        DhParametersDecoder()

    override fun parametersGenerator(primeSize: BinarySize): MaterialGenerator<DH.Parameters> =
        DhParametersGenerator(primeSize)

    private class DhPrivateKeyDecoder :
        Openssl3PrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>("DH") {
        override fun inputType(format: DH.PrivateKey.Format): String = when (format) {
            DH.PrivateKey.Format.DER -> "DER"
            DH.PrivateKey.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PrivateKey {
            return DhPrivateKey(key, publicKey = null, extractParametersFromKey(key))
        }
    }

    private class DhPublicKeyDecoder :
        Openssl3PublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>("DH") {
        override fun inputType(format: DH.PublicKey.Format): String = when (format) {
            DH.PublicKey.Format.DER -> "DER"
            DH.PublicKey.Format.PEM -> "PEM"
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PublicKey {
            return DhPublicKey(key, extractParametersFromKey(key))
        }
    }

    private class DhKeyGenerator(
        private val parameters: DH.Parameters,
    ) : KeyGenerator<DH.KeyPair> {
        @OptIn(UnsafeNumber::class)
        override fun generateKeyBlocking(): DH.KeyPair = memScoped {
            // Strip leading zeros to get proper unsigned big-endian representation for OpenSSL
            val pBytes = parameters.p.encodeToByteArray().dropLeadingZeros()
            val gBytes = parameters.g.encodeToByteArray().dropLeadingZeros()

            // First, create domain parameters from p and g
            val fromDataContext = checkError(EVP_PKEY_CTX_new_from_name(null, "DH", null))
            val domainParams: CPointer<EVP_PKEY>
            try {
                checkError(EVP_PKEY_fromdata_init(fromDataContext))
                val paramsKeyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(
                    EVP_PKEY_fromdata(
                        ctx = fromDataContext,
                        ppkey = paramsKeyVar.ptr,
                        selection = EVP_PKEY_KEY_PARAMETERS,
                        param = OSSL_PARAM_array(
                            OSSL_PARAM_construct_BN("p".cstr.ptr, pBytes.safeRefToU(0), pBytes.size.convert()),
                            OSSL_PARAM_construct_BN("g".cstr.ptr, gBytes.safeRefToU(0), gBytes.size.convert())
                        )
                    )
                )
                domainParams = checkError(paramsKeyVar.value)
            } finally {
                EVP_PKEY_CTX_free(fromDataContext)
            }

            // Now generate a key pair using the domain parameters
            val keygenContext = checkError(EVP_PKEY_CTX_new_from_pkey(null, domainParams, null))
            try {
                checkError(EVP_PKEY_keygen_init(keygenContext))
                val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(keygenContext, pkeyVar.ptr))
                val pkey = checkError(pkeyVar.value)
                val publicKey = DhPublicKey(pkey.upRef(), parameters)
                DhKeyPair(
                    publicKey = publicKey,
                    privateKey = DhPrivateKey(pkey, publicKey, parameters)
                )
            } finally {
                EVP_PKEY_CTX_free(keygenContext)
                EVP_PKEY_free(domainParams)
            }
        }
    }

    private class DhKeyPair(
        override val publicKey: DH.PublicKey,
        override val privateKey: DH.PrivateKey,
    ) : DH.KeyPair

    private class DhPrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: DH.PublicKey?,
        override val parameters: DH.Parameters,
    ) : DH.PrivateKey,
        Openssl3PrivateKeyEncodable<DH.PrivateKey.Format, DH.PublicKey>(key, publicKey),
        SharedSecretGenerator<DH.PublicKey> {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): DH.PublicKey = DhPublicKey(key, parameters)

        override val x: BigInt get() = extractBigNumFromKey(key, "priv")

        override fun outputType(format: DH.PrivateKey.Format): String = when (format) {
            DH.PrivateKey.Format.DER -> "DER"
            DH.PrivateKey.Format.PEM -> "PEM"
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey)

            return deriveDhSharedSecret(publicKey = other.key, privateKey = key)
        }
    }

    private class DhPublicKey(
        key: CPointer<EVP_PKEY>,
        override val parameters: DH.Parameters,
    ) : DH.PublicKey, Openssl3PublicKeyEncodable<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        override val y: BigInt get() = extractBigNumFromKey(key, "pub")

        override fun outputType(format: DH.PublicKey.Format): String = when (format) {
            DH.PublicKey.Format.DER -> "DER"
            DH.PublicKey.Format.PEM -> "PEM"
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey)

            return deriveDhSharedSecret(publicKey = key, privateKey = other.key)
        }
    }

    private class DhParametersDecoder : MaterialDecoder<DH.Parameters.Format, DH.Parameters> {
        override fun decodeFromByteArrayBlocking(format: DH.Parameters.Format, bytes: ByteArray): DH.Parameters {
            val derBytes = when (format) {
                DH.Parameters.Format.DER -> bytes
                DH.Parameters.Format.PEM -> unwrapDhParametersPem(bytes)
            }
            val (prime, base) = decodeDhParametersFromDer(derBytes)
            return Openssl3DhParameters(prime, base)
        }
    }

    private class DhParametersGenerator(
        private val primeSize: BinarySize,
    ) : MaterialGenerator<DH.Parameters> {
        @OptIn(UnsafeNumber::class)
        override fun generateBlocking(): DH.Parameters = memScoped {
            val context = checkError(EVP_PKEY_CTX_new_from_name(null, "DH", null))
            try {
                checkError(EVP_PKEY_paramgen_init(context))

                // Set the prime bit length
                val primeBits = alloc<UIntVar>()
                primeBits.value = primeSize.inBits.toUInt()
                checkError(
                    EVP_PKEY_CTX_set_params(
                        context,
                        OSSL_PARAM_array(
                            OSSL_PARAM_construct_uint("pbits".cstr.ptr, primeBits.ptr)
                        )
                    )
                )

                // Generate parameters
                val paramsKeyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(context, paramsKeyVar.ptr))
                val paramsKey = checkError(paramsKeyVar.value)

                try {
                    // Extract p and g
                    val p = extractBigNumFromKey(paramsKey, "p")
                    val g = extractBigNumFromKey(paramsKey, "g")

                    Openssl3DhParameters(p, g)
                } finally {
                    EVP_PKEY_free(paramsKey)
                }
            } finally {
                EVP_PKEY_CTX_free(context)
            }
        }
    }

    private class Openssl3DhParameters(
        override val p: BigInt,
        override val g: BigInt,
    ) : DH.Parameters {
        override fun keyPairGenerator(): KeyGenerator<DH.KeyPair> = DhKeyGenerator(this)

        override fun encodeToByteArrayBlocking(format: DH.Parameters.Format): ByteArray = when (format) {
            DH.Parameters.Format.DER -> encodeDhParametersToDer(p, g)
            DH.Parameters.Format.PEM -> wrapDhParametersPem(encodeDhParametersToDer(p, g))
        }
    }

    private fun extractParametersFromKey(key: CPointer<EVP_PKEY>): DH.Parameters {
        val p = extractBigNumFromKey(key, "p")
        val g = extractBigNumFromKey(key, "g")
        return Openssl3DhParameters(p, g)
    }
}

@OptIn(UnsafeNumber::class)
private fun extractBigNumFromKey(key: CPointer<EVP_PKEY>, paramName: String): BigInt = memScoped {
    val bnVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, paramName, bnVar.ptr))
    val bn = checkError(bnVar.value)

    try {
        val size = (checkError(BN_num_bits(bn)) + 7) / 8
        val bytes = ByteArray(size)
        checkError(BN_bn2bin(bn, bytes.refToU(0)))
        bytes.decodeToBigInt()
    } finally {
        BN_free(bn)
    }
}

@OptIn(UnsafeNumber::class)
private fun deriveDhSharedSecret(
    publicKey: CPointer<EVP_PKEY>,
    privateKey: CPointer<EVP_PKEY>,
): ByteArray = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
    try {
        checkError(EVP_PKEY_derive_init(context))
        checkError(EVP_PKEY_derive_set_peer(context, publicKey))
        val secretSize = alloc<size_tVar>()
        checkError(EVP_PKEY_derive(context, null, secretSize.ptr))
        val secret = ByteArray(secretSize.value.toInt())
        checkError(EVP_PKEY_derive(context, secret.refToU(0), secretSize.ptr))
        secret
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}

// Drops leading zero bytes but keeps at least one byte (returns [0] for all-zero input)
private fun ByteArray.dropLeadingZeros(): ByteArray {
    val firstNonZero = indexOfFirst { it != 0.toByte() }
    return when {
        firstNonZero == -1 -> byteArrayOf(0)  // all zeros
        firstNonZero == 0  -> this              // no leading zeros
        else               -> copyOfRange(firstNonZero, size)
    }
}
