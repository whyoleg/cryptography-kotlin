/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3Scrypt : Scrypt {
    override fun secretDerivation(
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        maximumMemoryBytes: Long,
        outputSize: BinarySize,
        salt: ByteArray,
    ): SecretDerivation {
        validateScryptParameters(cost, blockSize, parallelization, maximumMemoryBytes, outputSize)
        return Openssl3ScryptSecretDerivation(
            cost = cost,
            blockSize = blockSize,
            parallelization = parallelization,
            outputSize = outputSize,
            salt = salt.copyOf(),
            maximumMemoryBytes = maximumMemoryBytes,
        )
    }
}

private class Openssl3ScryptSecretDerivation(
    private val cost: Int,
    private val blockSize: Int,
    private val parallelization: Int,
    private val outputSize: BinarySize,
    private val salt: ByteArray,
    private val maximumMemoryBytes: Long,
) : SecretDerivation {
    private val kdf = checkError(EVP_KDF_fetch(null, "SCRYPT", null))

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
                        OSSL_PARAM_construct_octet_string("pass".cstr.ptr, input.safeRefTo(0), input.size.convert()),
                        OSSL_PARAM_construct_octet_string("salt".cstr.ptr, salt.safeRefTo(0), salt.size.convert()),
                        OSSL_PARAM_construct_uint64("n".cstr.ptr, alloc(cost.toULong()).ptr),
                        OSSL_PARAM_construct_uint64("r".cstr.ptr, alloc(blockSize.toULong()).ptr),
                        OSSL_PARAM_construct_uint64("p".cstr.ptr, alloc(parallelization.toULong()).ptr),
                        OSSL_PARAM_construct_uint64("maxmem_bytes".cstr.ptr, alloc(maximumMemoryBytes.toULong()).ptr),
                    )
                )
            )
            output
        } finally {
            EVP_KDF_CTX_free(context)
        }
    }
}
