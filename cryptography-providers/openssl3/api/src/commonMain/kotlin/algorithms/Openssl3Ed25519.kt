/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal object Openssl3Ed25519 : ED25519 {
    override fun publicKeyDecoder(): KeyDecoder<ED25519.PublicKey.Format, ED25519.PublicKey> = Ed25519PublicKeyDecoder

    override fun privateKeyDecoder(): KeyDecoder<ED25519.PrivateKey.Format, ED25519.PrivateKey> = Ed25519PrivateKeyDecoder

    override fun keyPairGenerator(): KeyGenerator<ED25519.KeyPair> = Ed25519KeyGenerator

    private object Ed25519PrivateKeyDecoder : Openssl3PrivateKeyDecoder<ED25519.PrivateKey.Format, ED25519.PrivateKey>("ED25519") {
        override fun inputType(format: ED25519.PrivateKey.Format): String = when (format) {
            ED25519.PrivateKey.Format.DER -> "DER"
            ED25519.PrivateKey.Format.PEM -> "PEM"
            ED25519.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: ED25519.PrivateKey.Format, bytes: ByteArray): ED25519.PrivateKey = when (format) {
            ED25519.PrivateKey.Format.RAW -> Ed25519PrivateKey(decodePrivateRawKey(bytes), publicKey = null)
            else                          -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ED25519.PrivateKey = Ed25519PrivateKey(key, publicKey = null)
    }

    private object Ed25519PublicKeyDecoder : Openssl3PublicKeyDecoder<ED25519.PublicKey.Format, ED25519.PublicKey>("ED25519") {
        override fun inputType(format: ED25519.PublicKey.Format): String = when (format) {
            ED25519.PublicKey.Format.DER -> "DER"
            ED25519.PublicKey.Format.PEM -> "PEM"
            ED25519.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: ED25519.PublicKey.Format, bytes: ByteArray): ED25519.PublicKey = when (format) {
            ED25519.PublicKey.Format.RAW -> Ed25519PublicKey(decodePublicRawKey(bytes))
            else                         -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ED25519.PublicKey = Ed25519PublicKey(key)
    }

    private object Ed25519KeyGenerator : Openssl3KeyPairGenerator<ED25519.KeyPair>("ED25519") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): ED25519.KeyPair {
            val publicKey = Ed25519PublicKey(keyPair)
            return Ed25519KeyPair(
                publicKey = publicKey,
                privateKey = Ed25519PrivateKey(keyPair, publicKey)
            )
        }
    }

    private class Ed25519KeyPair(
        override val publicKey: ED25519.PublicKey,
        override val privateKey: ED25519.PrivateKey,
    ) : ED25519.KeyPair

    private class Ed25519PrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: ED25519.PublicKey?,
    ) : ED25519.PrivateKey, Openssl3PrivateKeyEncodable<ED25519.PrivateKey.Format, ED25519.PublicKey>(key, publicKey) {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): ED25519.PublicKey = Ed25519PublicKey(key)

        override fun outputType(format: ED25519.PrivateKey.Format): String = when (format) {
            ED25519.PrivateKey.Format.DER -> "DER"
            ED25519.PrivateKey.Format.PEM -> "PEM"
            ED25519.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: ED25519.PrivateKey.Format): ByteArray = when (format) {
            ED25519.PrivateKey.Format.RAW -> encodeEd25519PrivateRawKey(key)
            else                          -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureGenerator(): SignatureGenerator = Ed25519SignatureGenerator(key)
    }

    private class Ed25519PublicKey(
        key: CPointer<EVP_PKEY>,
    ) : ED25519.PublicKey, Openssl3PublicKeyEncodable<ED25519.PublicKey.Format>(key) {
        override fun outputType(format: ED25519.PublicKey.Format): String = when (format) {
            ED25519.PublicKey.Format.DER -> "DER"
            ED25519.PublicKey.Format.PEM -> "PEM"
            ED25519.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: ED25519.PublicKey.Format): ByteArray = when (format) {
            ED25519.PublicKey.Format.RAW -> encodeEd25519PublicRawKey(key)
            else                         -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureVerifier(): SignatureVerifier = Ed25519SignatureVerifier(key)
    }
}

// ED25519 uses one-shot signing (internal SHA-512 hashing, no streaming support)
private class Ed25519SignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
) : SignatureGenerator {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    override fun createSignFunction(): SignFunction = AccumulatingSignFunction(::sign)

    @OptIn(UnsafeNumber::class)
    private fun sign(data: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
            checkError(
                EVP_DigestSignInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = null, // ED25519 uses internal hashing
                    libctx = null,
                    props = null,
                    pkey = privateKey,
                    params = null
                )
            )
            data.usePinned { dataPin ->
                val siglen = alloc<size_tVar>()
                // Get required signature size
                checkError(
                    EVP_DigestSign(
                        ctx = context,
                        sigret = null,
                        siglen = siglen.ptr,
                        tbs = dataPin.safeAddressOfU(0),
                        tbslen = data.size.convert()
                    )
                )
                val signature = ByteArray(siglen.value.convert())
                // Actually sign
                checkError(
                    EVP_DigestSign(
                        ctx = context,
                        sigret = signature.safeRefToU(0),
                        siglen = siglen.ptr,
                        tbs = dataPin.safeAddressOfU(0),
                        tbslen = data.size.convert()
                    )
                )
                signature.ensureSizeExactly(siglen.value.convert())
            }
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}

// ED25519 uses one-shot verification (internal SHA-512 hashing, no streaming support)
private class Ed25519SignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
) : SignatureVerifier {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    override fun createVerifyFunction(): VerifyFunction = AccumulatingVerifyFunction(::verify)

    @OptIn(UnsafeNumber::class)
    private fun verify(data: ByteArray, signature: ByteArray): String? = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
            checkError(
                EVP_DigestVerifyInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = null, // ED25519 uses internal hashing
                    libctx = null,
                    props = null,
                    pkey = publicKey,
                    params = null
                )
            )
            val result = data.usePinned { dataPin ->
                signature.usePinned { sigPin ->
                    EVP_DigestVerify(
                        ctx = context,
                        sigret = sigPin.safeAddressOfU(0),
                        siglen = signature.size.convert(),
                        tbs = dataPin.safeAddressOfU(0),
                        tbslen = data.size.convert()
                    )
                }
            }
            // 0     - means verification failed
            // 1     - means verification succeeded
            // other - means error
            if (result != 0) checkError(result)
            if (result == 1) null else "Signature verification failed"
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}

// ED25519 RAW key encoding/decoding helpers

@OptIn(UnsafeNumber::class)
private fun decodePublicRawKey(input: ByteArray): CPointer<EVP_PKEY> = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "ED25519", null))
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
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "ED25519", null))
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
private fun encodeEd25519PublicRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val outVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "pub", null, 0.convert(), outVar.ptr))
    val output = ByteArray(outVar.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "pub", output.safeRefToU(0), output.size.convert(), outVar.ptr))
    output.ensureSizeExactly(outVar.value.convert())
}

@OptIn(UnsafeNumber::class)
private fun encodeEd25519PrivateRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val outVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "priv", null, 0.convert(), outVar.ptr))
    val output = ByteArray(outVar.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "priv", output.safeRefToU(0), output.size.convert(), outVar.ptr))
    output.ensureSizeExactly(outVar.value.convert())
}
