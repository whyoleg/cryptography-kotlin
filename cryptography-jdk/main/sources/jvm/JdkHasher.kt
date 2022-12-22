package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*

internal class JdkHasherProvider(
    private val state: JdkCryptographyState,
    private val algorithm: String,
) : HasherProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Hasher = JdkHasher(state, algorithm)
}

internal class JdkHasher(
    private val state: JdkCryptographyState,
    algorithm: String,
) : Hasher {
    private val messageDigest = threadLocal { state.provider.messageDigest(algorithm) }
    override val digestSize: Int get() = messageDigest.get().digestLength

    override fun hashBlocking(dataInput: Buffer): Buffer {
        val messageDigest = messageDigest.get()
        messageDigest.reset()
        return messageDigest.digest(dataInput)
    }

    override fun hashBlocking(dataInput: Buffer, digestOutput: Buffer): Buffer {
        val messageDigest = messageDigest.get()
        messageDigest.reset()
        messageDigest.update(dataInput)
        messageDigest.digest(digestOutput, 0, digestOutput.size)
        return digestOutput
    }

    override fun hashFunction(): HashFunction {
        TODO("Not yet implemented")
    }

    override suspend fun hash(dataInput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput) }
    }

    override suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput, digestOutput) }
    }
}
