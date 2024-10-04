/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.jdk.*

internal class JdkDigest(
    state: JdkCryptographyState,
    algorithm: String,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest {
    private val messageDigest = state.messageDigest(algorithm)
    override fun hasher(): Hasher = this
    override fun createHashFunction(): HashFunction = JdkHashFunction(messageDigest.borrowResource().also {
        it.access().reset()
    })
}

private class JdkHashFunction(private val messageDigest: Pooled.Resource<JMessageDigest>) : HashFunction {
    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)

        val messageDigest = messageDigest.access()
        messageDigest.update(source, startIndex, endIndex - startIndex)
    }

    override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val messageDigest = messageDigest.access()

        checkBounds(destination.size, destinationOffset, destinationOffset + messageDigest.digestLength)

        return messageDigest.digest(destination, destinationOffset, messageDigest.digestLength).also { close() }
    }

    override fun hashToByteArray(): ByteArray {
        val messageDigest = messageDigest.access()
        return messageDigest.digest().also { close() }
    }

    override fun close() {
        messageDigest.close()
    }
}
