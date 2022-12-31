package dev.whyoleg.cryptography.jdk.operations

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

    override fun hashBlocking(dataInput: Buffer, digestOutput: Buffer): Buffer = messageDigest.use { messageDigest ->
        messageDigest.reset()
        messageDigest.update(dataInput)
        messageDigest.digest(digestOutput, 0, digestOutput.size)
        digestOutput
    }

    override suspend fun hash(dataInput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput) }
    }

    override suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput, digestOutput) }
    }
}
