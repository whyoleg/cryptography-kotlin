/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

internal object Openssl3Scrypt : Scrypt {
    override fun secretDerivation(
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        outputSize: BinarySize,
        salt: ByteArray,
        maximumMemoryBytes: Long,
    ): SecretDerivation {
        validateScryptParameters(cost, blockSize, parallelization, outputSize, maximumMemoryBytes)
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

private fun validateScryptParameters(
    cost: Int,
    blockSize: Int,
    parallelization: Int,
    outputSize: BinarySize,
    maximumMemoryBytes: Long,
) {
    require(cost > 1 && (cost and (cost - 1)) == 0) { "cost must be greater than 1 and a power of two" }
    require(blockSize >= 1) { "blockSize must be at least 1" }
    require(parallelization >= 1) { "parallelization must be at least 1" }
    require(outputSize.inBytes >= 1) { "outputSize must be at least 1 byte" }
    require(maximumMemoryBytes > 0) { "maximumMemoryBytes must be greater than 0" }
    require(blockSize != 1 || cost < 65536) { "cost must be less than 65536 when blockSize is 1" }

    val blockSizeBytesWithBits = checkedMultiply(1024L, blockSize.toLong(), "blockSize")
    val maximumParallelization = Int.MAX_VALUE.toLong() / blockSizeBytesWithBits
    require(parallelization.toLong() <= maximumParallelization) {
        "parallelization is too large for blockSize"
    }

    val costAndOverhead = checkedAdd(
        checkedAdd(cost.toLong(), checkedMultiply(2L, parallelization.toLong(), "parallelization"), "scrypt memory"),
        4L,
        "scrypt memory",
    )
    val minimumMemoryBytes = checkedMultiply(
        checkedMultiply(128L, blockSize.toLong(), "blockSize"),
        costAndOverhead,
        "scrypt memory",
    )
    require(minimumMemoryBytes <= maximumMemoryBytes) {
        "maximumMemoryBytes must be at least $minimumMemoryBytes for these scrypt parameters"
    }
}

private fun checkedAdd(left: Long, right: Long, parameter: String): Long {
    require(left <= Long.MAX_VALUE - right) { "$parameter is too large" }
    return left + right
}

private fun checkedMultiply(left: Long, right: Long, parameter: String): Long {
    require(left == 0L || right <= Long.MAX_VALUE / left) { "$parameter is too large" }
    return left * right
}
