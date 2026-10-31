/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal object Openssl3Hkdf : HKDF {
    val kdf = NativeResource(checkError(EVP_KDF_fetch(null, "HKDF", null)), ::EVP_KDF_free)

    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray?,
    ): SecretDerivation {
        val hashAlgorithm = hashAlgorithmName(digest)
        return Openssl3HkdfSecretDerivation(
            hashAlgorithm = hashAlgorithm,
            outputSize = outputSize,
            salt = salt?.takeIf(ByteArray::isNotEmpty) ?: ByteArray(digestSize(hashAlgorithm)),
            info = info?.takeIf(ByteArray::isNotEmpty),
        )
    }
}

private class Openssl3HkdfSecretDerivation(
    private val hashAlgorithm: String,
    private val outputSize: BinarySize,
    private val salt: ByteArray,
    private val info: ByteArray?,
) : SecretDerivation {
    @OptIn(UnsafeNumber::class)
    override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_KDF_CTX_new(Openssl3Hkdf.kdf.access()))
        try {
            val output = ByteArray(outputSize.inBytes)
            checkError(
                EVP_KDF_derive(
                    ctx = context,
                    key = output.refToU(0),
                    keylen = output.size.convert(),
                    params = OSSL_PARAM_array(
                        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert()),
                        OSSL_PARAM_construct_octet_string("salt".cstr.ptr, salt.safeRefTo(0), salt.size.convert()),
                        info?.let { OSSL_PARAM_construct_octet_string("info".cstr.ptr, it.safeRefTo(0), it.size.convert()) },
                        OSSL_PARAM_construct_octet_string("key".cstr.ptr, input.safeRefTo(0), input.size.convert())
                    )
                )
            )
            output
        } finally {
            EVP_KDF_CTX_free(context)
        }
    }
}
