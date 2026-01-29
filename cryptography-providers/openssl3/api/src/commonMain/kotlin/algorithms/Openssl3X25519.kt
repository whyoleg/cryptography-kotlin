/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal object Openssl3X25519 : X25519 {
    override fun publicKeyDecoder(): KeyDecoder<X25519.PublicKey.Format, X25519.PublicKey> = X25519PublicKeyDecoder

    override fun privateKeyDecoder(): KeyDecoder<X25519.PrivateKey.Format, X25519.PrivateKey> = X25519PrivateKeyDecoder

    override fun keyPairGenerator(): KeyGenerator<X25519.KeyPair> = X25519KeyGenerator

    private object X25519PrivateKeyDecoder : Openssl3PrivateKeyDecoder<X25519.PrivateKey.Format, X25519.PrivateKey>("X25519") {
        override fun inputType(format: X25519.PrivateKey.Format): String = when (format) {
            X25519.PrivateKey.Format.DER -> "DER"
            X25519.PrivateKey.Format.PEM -> "PEM"
            X25519.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: X25519.PrivateKey.Format, bytes: ByteArray): X25519.PrivateKey = when (format) {
            X25519.PrivateKey.Format.RAW -> X25519PrivateKey(decodePrivateRawKey(bytes), publicKey = null)
            else                         -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): X25519.PrivateKey = X25519PrivateKey(key, publicKey = null)
    }

    private object X25519PublicKeyDecoder : Openssl3PublicKeyDecoder<X25519.PublicKey.Format, X25519.PublicKey>("X25519") {
        override fun inputType(format: X25519.PublicKey.Format): String = when (format) {
            X25519.PublicKey.Format.DER -> "DER"
            X25519.PublicKey.Format.PEM -> "PEM"
            X25519.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: X25519.PublicKey.Format, bytes: ByteArray): X25519.PublicKey = when (format) {
            X25519.PublicKey.Format.RAW -> X25519PublicKey(decodePublicRawKey(bytes))
            else                        -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): X25519.PublicKey = X25519PublicKey(key)
    }

    private object X25519KeyGenerator : Openssl3KeyPairGenerator<X25519.KeyPair>("X25519") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): X25519.KeyPair {
            val publicKey = X25519PublicKey(keyPair)
            return X25519KeyPair(
                publicKey = publicKey,
                privateKey = X25519PrivateKey(keyPair, publicKey)
            )
        }
    }

    private class X25519KeyPair(
        override val publicKey: X25519.PublicKey,
        override val privateKey: X25519.PrivateKey,
    ) : X25519.KeyPair

    private class X25519PrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: X25519.PublicKey?,
    ) : X25519.PrivateKey,
        Openssl3PrivateKeyEncodable<X25519.PrivateKey.Format, X25519.PublicKey>(key, publicKey),
        SharedSecretGenerator<X25519.PublicKey> {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): X25519.PublicKey = X25519PublicKey(key)

        override fun outputType(format: X25519.PrivateKey.Format): String = when (format) {
            X25519.PrivateKey.Format.DER -> "DER"
            X25519.PrivateKey.Format.PEM -> "PEM"
            X25519.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: X25519.PrivateKey.Format): ByteArray = when (format) {
            X25519.PrivateKey.Format.RAW -> encodeX25519PrivateRawKey(key)
            else                         -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<X25519.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: X25519.PublicKey): ByteArray {
            check(other is X25519PublicKey)
            return deriveSharedSecret(publicKey = other.key, privateKey = key)
        }
    }

    private class X25519PublicKey(
        key: CPointer<EVP_PKEY>,
    ) : X25519.PublicKey,
        Openssl3PublicKeyEncodable<X25519.PublicKey.Format>(key),
        SharedSecretGenerator<X25519.PrivateKey> {
        override fun outputType(format: X25519.PublicKey.Format): String = when (format) {
            X25519.PublicKey.Format.DER -> "DER"
            X25519.PublicKey.Format.PEM -> "PEM"
            X25519.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: X25519.PublicKey.Format): ByteArray = when (format) {
            X25519.PublicKey.Format.RAW -> encodeX25519PublicRawKey(key)
            else                        -> super.encodeToByteArrayBlocking(format)
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<X25519.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: X25519.PrivateKey): ByteArray {
            check(other is X25519PrivateKey)
            return deriveSharedSecret(publicKey = key, privateKey = other.key)
        }
    }
}

// X25519 RAW key encoding/decoding helpers

@OptIn(UnsafeNumber::class)
private fun decodePublicRawKey(input: ByteArray): CPointer<EVP_PKEY> = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "X25519", null))
    try {
        checkError(EVP_PKEY_fromdata_init(context))
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(
            EVP_PKEY_fromdata(
                ctx = context,
                ppkey = pkeyVar.ptr,
                selection = EVP_PKEY_PUBLIC_KEY,
                param = OSSL_PARAM_array(
                    OSSL_PARAM_construct_octet_string("pub".cstr.ptr, input.safeRefToU(0), input.size.convert())
                )
            )
        )
        checkError(pkeyVar.value)
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}

@OptIn(UnsafeNumber::class)
private fun decodePrivateRawKey(input: ByteArray): CPointer<EVP_PKEY> = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "X25519", null))
    try {
        checkError(EVP_PKEY_fromdata_init(context))
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(
            EVP_PKEY_fromdata(
                ctx = context,
                ppkey = pkeyVar.ptr,
                selection = EVP_PKEY_KEYPAIR, // KEYPAIR to derive public key from private
                param = OSSL_PARAM_array(
                    OSSL_PARAM_construct_octet_string("priv".cstr.ptr, input.safeRefToU(0), input.size.convert())
                )
            )
        )
        checkError(pkeyVar.value)
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}

@OptIn(UnsafeNumber::class)
private fun encodeX25519PublicRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val outVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "pub", null, 0.convert(), outVar.ptr))
    val output = ByteArray(outVar.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "pub", output.safeRefToU(0), output.size.convert(), outVar.ptr))
    output.ensureSizeExactly(outVar.value.convert())
}

@OptIn(UnsafeNumber::class)
private fun encodeX25519PrivateRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val outVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "priv", null, 0.convert(), outVar.ptr))
    val output = ByteArray(outVar.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "priv", output.safeRefToU(0), output.size.convert(), outVar.ptr))
    output.ensureSizeExactly(outVar.value.convert())
}
