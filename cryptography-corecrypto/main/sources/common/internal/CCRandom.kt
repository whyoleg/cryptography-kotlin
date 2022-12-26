package dev.whyoleg.cryptography.corecrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.random.*

internal class CCRandom(
    private val state: CoreCryptoState,
) : RandomizerProvider<CryptographyOperationParameters.Empty>(), Randomizer {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Randomizer = this

    override fun randomBlocking(size: Int): Buffer {
        return randomBlocking(ByteArray(size))
    }

    override fun randomBlocking(output: Buffer): Buffer {
        if (
            CCRandomGenerateBytes(output.refTo(0), output.size.convert()) != kCCSuccess
        ) throw CryptographyException("CCRandomGenerateBytes failed")
        return output
    }

    override suspend fun random(size: Int): Buffer {
        return state.execute { randomBlocking(size) }
    }

    override suspend fun random(output: Buffer): Buffer {
        return state.execute { randomBlocking(output) }
    }

    override fun randomInstance(): Random {
        TODO("Not yet implemented")
    }
}
