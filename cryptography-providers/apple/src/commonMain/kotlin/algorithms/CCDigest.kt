/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*

internal class CCDigest<CTX : CPointed>(
    private val hashAlgorithm: CCHashAlgorithm<CTX>,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest {
    override fun hasher(): Hasher = this
    override fun createHashFunction(): HashFunction {
        val context = hashAlgorithm.alloc()
        // TODO: error handle
        hashAlgorithm.ccInit(context)
        return CCHashFunction(
            algorithm = hashAlgorithm,
            context = Resource(context, nativeHeap::free)
        )
    }
}

private class CCHashFunction<CTX : CPointed>(
    private val algorithm: CCHashAlgorithm<CTX>,
    private val context: Resource<CPointer<CTX>>,
) : HashFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {
    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)

        val context = context.access()
        source.usePinned {
            check(algorithm.ccUpdate(context, it.safeAddressOf(startIndex), (endIndex - startIndex).convert()) > 0)
        }
    }

    override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + algorithm.digestSize)

        val context = context.access()
        destination.usePinned {
            check(algorithm.ccFinal(context, it.safeAddressOf(destinationOffset).reinterpret()) > 0)
        }
        close()
        return algorithm.digestSize
    }

    override fun hashToByteArray(): ByteArray {
        val output = ByteArray(algorithm.digestSize)
        hashIntoByteArray(output)
        return output
    }
}
