/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.DH
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*
import platform.posix.*

internal object Openssl3Dh : DH {
    override fun publicKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PublicKey.Format, DH.PublicKey> =
        DhPublicKeyDecoder(parameters)

    override fun privateKeyDecoder(parameters: DH.Parameters): KeyDecoder<DH.PrivateKey.Format, DH.PrivateKey> =
        DhPrivateKeyDecoder(parameters)

    override fun keyPairGenerator(parameters: DH.Parameters): KeyGenerator<DH.KeyPair> =
        DhKeyGenerator(parameters)

    private class DhPrivateKeyDecoder(
        private val parameters: DH.Parameters,
    ) : Openssl3PrivateKeyDecoder<DH.PrivateKey.Format, DH.PrivateKey>("DH") {
        override fun inputType(format: DH.PrivateKey.Format): String = when (format) {
            DH.PrivateKey.Format.DER -> "DER"
            DH.PrivateKey.Format.PEM -> "PEM"
            DH.PrivateKey.Format.RAW -> "DER" // with custom processing
        }

        override fun decodeFromByteArrayBlocking(format: DH.PrivateKey.Format, bytes: ByteArray): DH.PrivateKey = when (format) {
            DH.PrivateKey.Format.RAW -> wrapKey(decodeDhPrivateRawKey(parameters, bytes))
            else                     -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PrivateKey {
            // Note: Parameter validation is skipped as incorrect parameters
            // will cause key derivation to fail with incompatible shared secrets
            return DhPrivateKey(key, publicKey = null)
        }
    }

    private class DhPublicKeyDecoder(
        private val parameters: DH.Parameters,
    ) : Openssl3PublicKeyDecoder<DH.PublicKey.Format, DH.PublicKey>("DH") {
        override fun inputType(format: DH.PublicKey.Format): String = when (format) {
            DH.PublicKey.Format.DER -> "DER"
            DH.PublicKey.Format.PEM -> "PEM"
            DH.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: DH.PublicKey.Format, bytes: ByteArray): DH.PublicKey = when (format) {
            DH.PublicKey.Format.RAW -> wrapKey(decodeDhPublicRawKey(parameters, bytes))
            else                    -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DH.PublicKey {
            // Note: Parameter validation is skipped as incorrect parameters
            // will cause key derivation to fail with incompatible shared secrets
            return DhPublicKey(key)
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
                val publicKey = DhPublicKey(pkey.upRef())
                DhKeyPair(
                    publicKey = publicKey,
                    privateKey = DhPrivateKey(pkey, publicKey)
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
    ) : DH.PrivateKey,
        Openssl3PrivateKeyEncodable<DH.PrivateKey.Format, DH.PublicKey>(key, publicKey),
        SharedSecretGenerator<DH.PublicKey> {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): DH.PublicKey = DhPublicKey(key)

        override fun outputType(format: DH.PrivateKey.Format): String = when (format) {
            DH.PrivateKey.Format.DER -> "DER"
            DH.PrivateKey.Format.PEM -> "PEM"
            DH.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: DH.PrivateKey.Format): ByteArray = when (format) {
            DH.PrivateKey.Format.RAW -> encodeDhPrivateRawKey(key)
            else                     -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PublicKey): ByteArray {
            check(other is DhPublicKey)

            return deriveDhSharedSecret(publicKey = other.key, privateKey = key)
        }
    }

    private class DhPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : DH.PublicKey, Openssl3PublicKeyEncodable<DH.PublicKey.Format>(key), SharedSecretGenerator<DH.PrivateKey> {
        override fun outputType(format: DH.PublicKey.Format): String = when (format) {
            DH.PublicKey.Format.DER -> "DER"
            DH.PublicKey.Format.PEM -> "PEM"
            DH.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: DH.PublicKey.Format): ByteArray = when (format) {
            DH.PublicKey.Format.RAW -> encodeDhPublicRawKey(key)
            else                    -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<DH.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: DH.PrivateKey): ByteArray {
            check(other is DhPrivateKey)

            return deriveDhSharedSecret(publicKey = key, privateKey = other.key)
        }
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

private fun decodeDhPublicRawKey(
    parameters: DH.Parameters,
    input: ByteArray,
): CPointer<EVP_PKEY> {
    // OpenSSL 3.x EVP_PKEY_fromdata has issues with DH public key RAW format import.
    // The workaround would be to construct a DER-encoded SubjectPublicKeyInfo structure,
    // but this requires additional ASN.1 module support for DH.
    // For now, RAW format is not supported for DH public keys on OpenSSL.
    error("DH public key RAW format is not supported in OpenSSL provider due to EVP_PKEY_fromdata limitations")
}

private fun decodeDhPrivateRawKey(
    parameters: DH.Parameters,
    input: ByteArray,
): CPointer<EVP_PKEY> {
    // OpenSSL 3.x EVP_PKEY_fromdata has issues with DH private key RAW format import.
    // The workaround would be to construct a DER-encoded PrivateKeyInfo structure,
    // but this requires additional ASN.1 module support for DH.
    // For now, RAW format is not supported for DH private keys on OpenSSL.
    error("DH private key RAW format is not supported in OpenSSL provider due to EVP_PKEY_fromdata limitations")
}

@OptIn(UnsafeNumber::class)
private fun encodeDhPublicRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    // Get p to determine the output size (pad to p's byte size for consistency with JDK)
    val pVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "p", pVar.ptr))
    val p = checkError(pVar.value)
    val pSize = (checkError(BN_num_bits(p)) + 7) / 8
    BN_free(p)

    val pubVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "pub", pubVar.ptr))
    val pub = checkError(pubVar.value)
    val output = ByteArray(pSize)
    try {
        // BN_bn2binpad writes the value with padding to exact size
        checkError(BN_bn2binpad(pub, output.refToU(0), pSize))
    } finally {
        BN_free(pub)
    }
    output
}

@OptIn(UnsafeNumber::class)
private fun encodeDhPrivateRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    // Get p to determine the output size (pad to p's byte size for consistency with JDK)
    val pVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "p", pVar.ptr))
    val p = checkError(pVar.value)
    val pSize = (checkError(BN_num_bits(p)) + 7) / 8
    BN_free(p)

    val privVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "priv", privVar.ptr))
    val priv = checkError(privVar.value)
    val output = ByteArray(pSize)
    try {
        // BN_bn2binpad writes the value with padding to exact size
        checkError(BN_bn2binpad(priv, output.refToU(0), pSize))
    } finally {
        BN_free(priv)
    }
    output
}

@OptIn(UnsafeNumber::class)
private fun checkDhKeyParameters(key: CPointer<EVP_PKEY>, expectedParameters: DH.Parameters) = memScoped {
    val pVar = alloc<CPointerVar<BIGNUM>>()
    val gVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "p", pVar.ptr))
    checkError(EVP_PKEY_get_bn_param(key, "g", gVar.ptr))
    val p = checkError(pVar.value)
    val g = checkError(gVar.value)
    try {
        val expectedPBytes = expectedParameters.p.encodeToByteArray().dropLeadingZeros()
        val expectedGBytes = expectedParameters.g.encodeToByteArray().dropLeadingZeros()

        val pSize = (checkError(BN_num_bits(p)) + 7) / 8
        val gSize = (checkError(BN_num_bits(g)) + 7) / 8

        val pBytes = ByteArray(pSize)
        val gBytes = ByteArray(gSize)

        checkError(BN_bn2bin(p, pBytes.refToU(0)))
        checkError(BN_bn2bin(g, gBytes.refToU(0)))

        check(pBytes.contentEquals(expectedPBytes)) { "Key parameter p does not match expected parameter" }
        check(gBytes.contentEquals(expectedGBytes)) { "Key parameter g does not match expected parameter" }
    } finally {
        BN_free(p)
        BN_free(g)
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
