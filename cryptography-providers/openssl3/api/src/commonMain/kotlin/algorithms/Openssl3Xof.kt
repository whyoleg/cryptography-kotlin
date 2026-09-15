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

internal class Openssl3Shake256 private constructor(
    private val md: CPointer<EVP_MD>,
) : XOF, SafeCloseable(SafeCloseAction(md, ::EVP_MD_free)) {
    constructor() : this(checkError(EVP_MD_fetch(null, "SHAKE-256", null)))

    override val id: CryptographyAlgorithmId<XOF> get() = SHAKE256

    override fun hasher(outputSize: BinarySize): Hasher {
        require(outputSize.inBytes > 0) { "Output size must be greater than 0" }
        return ShakeHasher(outputSize.inBytes)
    }

    private inner class ShakeHasher(private val outputSizeBytes: Int) : Hasher {
        override fun createHashFunction(): HashFunction = ShakeHashFunction(
            Resource(checkError(EVP_MD_CTX_new()), ::EVP_MD_CTX_free),
            outputSizeBytes,
        )
    }

    private inner class ShakeHashFunction(
        private val context: Resource<CPointer<EVP_MD_CTX>>,
        private val outputSizeBytes: Int,
    ) : HashFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {
        init {
            reset()
        }

        @OptIn(UnsafeNumber::class)
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)
            val _ = source.usePinned {
                checkError(EVP_DigestUpdate(context.access(), it.safeAddressOf(startIndex), (endIndex - startIndex).convert()))
            }
        }

        @OptIn(UnsafeNumber::class)
        override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            checkBounds(destination.size, destinationOffset, destinationOffset + outputSizeBytes)
            val _ = destination.usePinned {
                checkError(EVP_DigestFinalXOF(context.access(), it.safeAddressOfU(destinationOffset), outputSizeBytes.convert()))
            }
            reset()
            return outputSizeBytes
        }

        override fun hashToByteArray(): ByteArray {
            val output = ByteArray(outputSizeBytes)
            check(hashIntoByteArray(output) == outputSizeBytes)
            return output
        }
        override fun reset() {
            checkError(EVP_DigestInit(context.access(), md))
        }
    }
}
