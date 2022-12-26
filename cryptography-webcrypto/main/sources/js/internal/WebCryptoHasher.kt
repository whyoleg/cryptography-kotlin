package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal fun CryptographyAlgorithmIdentifier<Digest>.hashAlgorithmName(): String = when (this) {
    SHA1   -> "SHA-1"
    SHA256 -> "SHA-256"
    SHA384 -> "SHA-384"
    SHA512 -> "SHA-512"
    else   -> throw CryptographyException("Unsupported hash algorithm: ${this}")
}

internal class WebCryptoHasher private constructor(
    private val algorithm: String,
) : HasherProvider<CryptographyOperationParameters.Empty>(), Hasher {
    //TODO: lazy?
    companion object {
        val SHA1 = SHA(WebCryptoHasher("SHA-1"))
        val SHA256 = SHA(WebCryptoHasher("SHA-256"))
        val SHA384 = SHA(WebCryptoHasher("SHA-384"))
        val SHA512 = SHA(WebCryptoHasher("SHA-512"))
    }

    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Hasher = this

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
