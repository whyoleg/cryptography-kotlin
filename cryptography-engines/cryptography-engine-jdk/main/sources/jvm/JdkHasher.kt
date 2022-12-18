package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

internal class JdkHasher(
    private val state: JdkCryptographyState,
    algorithm: String,
) : SyncHasher {
    private val messageDigest = threadLocal { state.provider.messageDigest(algorithm) }
    override val digestSize: Int get() = messageDigest.get().digestLength

    override fun hash(dataInput: Buffer): Buffer {
        val messageDigest = messageDigest.get()
        messageDigest.reset()
        return messageDigest.digest(dataInput)
    }

    override fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        val messageDigest = messageDigest.get()
        messageDigest.reset()
        messageDigest.update(dataInput)
        messageDigest.digest(digestOutput, 0, digestOutput.size)
        return digestOutput
    }
}
