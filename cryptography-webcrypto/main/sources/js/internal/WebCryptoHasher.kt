package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoHasherProvider(
    private val algorithm: String,
) : HasherProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Hasher = WebCryptoHasher(algorithm)
}

internal class WebCryptoHasher(
    private val algorithm: String,
) : Hasher {
    override val digestSize: Int
        get() = TODO("Not yet implemented")

    override suspend fun hash(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.digest(algorithm, dataInput).await().toByteArray()
    }

    override suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        return hash(dataInput).copyInto(digestOutput)
    }

    override fun hashBlocking(dataInput: Buffer): Buffer = nonBlocking()
    override fun hashBlocking(dataInput: Buffer, digestOutput: Buffer): Buffer = nonBlocking()
    override fun hashFunction(): HashFunction = noFunction()
}
