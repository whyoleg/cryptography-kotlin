/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*

internal object Openssl3Hmac : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        val hashAlgorithm = hashAlgorithm(digest)
        val md = EVP_MD_fetch(null, hashAlgorithm, null)
        val keySizeBytes = EVP_MD_get_block_size(md)
        EVP_MD_free(md)
        return HmacKeyDecoder(hashAlgorithm, keySizeBytes)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        val hashAlgorithm = hashAlgorithm(digest)
        val md = EVP_MD_fetch(null, hashAlgorithm, null)
        val keySizeBytes = EVP_MD_get_block_size(md)
        EVP_MD_free(md)
        return HmacKeyGenerator(hashAlgorithm, keySizeBytes)
    }
}

private class HmacKeyDecoder(
    private val hashAlgorithm: String,
    private val keySizeBytes: Int,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromByteArrayBlocking(format: HMAC.Key.Format, bytes: ByteArray): HMAC.Key = when (format) {
        HMAC.Key.Format.RAW -> {
            require(bytes.size == keySizeBytes) { "Invalid key size: ${bytes.size}, expected: $keySizeBytes" }
            wrapKey(hashAlgorithm, bytes.copyOf())
        }
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacKeyGenerator(
    private val hashAlgorithm: String,
    private val keySizeBytes: Int,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(hashAlgorithm, key)
    }
}

private fun wrapKey(
    hashAlgorithm: String,
    key: ByteArray,
): HMAC.Key = object : HMAC.Key {
    private val signature = HmacSignature(hashAlgorithm, key)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
        HMAC.Key.Format.RAW -> key.copyOf()
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacSignature(
    private val hashAlgorithm: String,
    private val key: ByteArray,
) : SignatureGenerator, SignatureVerifier {

    @OptIn(UnsafeNumber::class)
    override fun generateSignatureBlocking(data: ByteArray): ByteArray = memScoped {
        val mac = checkError(EVP_MAC_fetch(null, "HMAC", null))
        val context = checkError(EVP_MAC_CTX_new(mac))
        try {
            checkError(
                EVP_MAC_init(
                    ctx = context,
                    key = key.refToU(0),
                    keylen = key.size.convert(),
                    params = OSSL_PARAM_array(
                        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert())
                    )
                )
            )
            checkError(EVP_MAC_update(context, data.safeRefToU(0), data.size.convert()))
            val signature = ByteArray(checkError(EVP_MAC_CTX_get_mac_size(context)).convert())
            checkError(EVP_MAC_final(context, signature.refToU(0), null, signature.size.convert()))
            signature
        } finally {
            EVP_MAC_CTX_free(context)
            EVP_MAC_free(mac)
        }
    }

    override fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean {
        return generateSignatureBlocking(data).contentEquals(signature)
    }
}
