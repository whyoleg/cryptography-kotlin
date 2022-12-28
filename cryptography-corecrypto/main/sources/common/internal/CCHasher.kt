package dev.whyoleg.cryptography.corecrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal class CCHasherProvider(
    private val state: CoreCryptoState,
    private val algorithm: CCHashAlgorithm,
) : HasherProvider<CryptographyOperationParameters.Empty>() {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Hasher = CCHasher(state, algorithm)
}

internal class CCHasher(
    private val state: CoreCryptoState,
    private val algorithm: CCHashAlgorithm,
) : Hasher {
    override val digestSize: Int
        get() = TODO("Not yet implemented")


    @OptIn(ExperimentalUnsignedTypes::class)
    override fun hashBlocking(dataInput: Buffer): Buffer {
        val output = ByteArray(digestSize)
        val result = algorithm.ccHash(
            dataInput.refTo(0),
            dataInput.size.convert(),
            output.asUByteArray().refTo(0)
        )
//        if (result != kCCSuccess) throw Exception("CC_SHA512 failed")
        return output
    }

    override fun hashBlocking(dataInput: Buffer, digestOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override suspend fun hash(dataInput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput) }
    }

    override suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        return state.execute { hashBlocking(dataInput, digestOutput) }
    }
}
