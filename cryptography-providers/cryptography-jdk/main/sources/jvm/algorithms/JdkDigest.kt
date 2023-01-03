package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.operations.hash.*

internal class JdkDigest(
    private val state: JdkCryptographyState,
    algorithm: String,
) : Hasher, Digest {
    override fun hasher(): Hasher = this

    private val messageDigest = state.messageDigest(algorithm)
    override val digestSize: Int get() = messageDigest.use { it.digestLength }

    override fun hashBlocking(dataInput: Buffer): Buffer = messageDigest.use { messageDigest ->
        messageDigest.reset()
        messageDigest.digest(dataInput)
    }

    override suspend fun hash(dataInput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput) }
    }
}
