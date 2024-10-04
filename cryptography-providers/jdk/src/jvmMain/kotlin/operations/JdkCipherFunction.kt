/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal open class JdkCipherFunction(
    private val cipher: Pooled.Resource<JCipher>,
) : BaseCipherFunction() {

    override val blockSize: Int
        get() = cipher.access().blockSize

    override fun maxOutputSize(inputSize: Int): Int {
        return cipher.access().getOutputSize(inputSize)
    }

    override fun transformToByteArray(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        checkBounds(source.size, startIndex, endIndex)

        val cipher = cipher.access()

        // java Cipher can return `null` when it produces nothing
        return cipher.update(
            /* input = */ source,
            /* inputOffset = */ startIndex,
            /* inputLen = */ endIndex - startIndex
        ) ?: EmptyByteArray
    }

    override fun transformIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        checkBounds(source.size, startIndex, endIndex)
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(endIndex - startIndex))

        val cipher = cipher.access()

        return cipher.update(
            /* input = */ source,
            /* inputOffset = */ startIndex,
            /* inputLen = */ endIndex - startIndex,
            /* output = */ destination,
            /* outputOffset = */ destinationOffset
        )
    }

    override fun finalizeToByteArray(): ByteArray {
        val cipher = cipher.access()

        return cipher.doFinal()
    }

    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(0))

        val cipher = cipher.access()

        return cipher.doFinal(
            /* output = */ destination,
            /* outputOffset = */ destinationOffset
        )
    }

    override fun transformAndFinalizeToByteArray(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        checkBounds(source.size, startIndex, endIndex)

        val cipher = cipher.access()

        return cipher.doFinal(
            /* input = */ source,
            /* inputOffset = */ startIndex,
            /* inputLen = */ endIndex - startIndex,
        )
    }

    override fun transformAndFinalizeIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        checkBounds(source.size, startIndex, endIndex)
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(endIndex - startIndex))

        val cipher = cipher.access()

        return cipher.doFinal(
            /* input = */ source,
            /* inputOffset = */ startIndex,
            /* inputLen = */ endIndex - startIndex,
            /* output = */ destination,
            /* outputOffset = */ destinationOffset
        )
    }

    override fun close() {
        cipher.close()
    }
}
