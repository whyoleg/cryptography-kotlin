/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3Pbkdf2 : PBKDF2 {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        iterations: Int,
        outputSize: BinarySize,
        salt: ByteArray,
    ): SecretDerivation = Openssl3Pbkdf2SecretDerivation(
        hashAlgorithm = hashAlgorithm(digest),
        salt = salt,
        iterations = iterations,
        outputSize = outputSize,
    )
}

private class Openssl3Pbkdf2SecretDerivation(
    private val hashAlgorithm: String,
    private val salt: ByteArray,
    private val iterations: Int,
    private val outputSize: BinarySize,
) : SecretDerivation {
    private val kdf = EVP_KDF_fetch(null, "PBKDF2", null)

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(kdf, ::EVP_KDF_free)

    @OptIn(UnsafeNumber::class)
    override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_KDF_CTX_new(kdf))
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
                        OSSL_PARAM_construct_uint32("iter".cstr.ptr, alloc(iterations.toUInt()).ptr),
                        OSSL_PARAM_construct_octet_string("pass".cstr.ptr, input.safeRefTo(0), input.size.convert())
                    )
                )
            )
            output
        } finally {
            EVP_KDF_CTX_free(context)
        }
    }
}
