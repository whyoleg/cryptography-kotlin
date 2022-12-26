package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.random.*
import dev.whyoleg.cryptography.webcrypto.external.*
import kotlin.random.*

internal object WebCryptoRandom : RandomizerProvider<CryptographyOperationParameters.Empty>(), Randomizer {
    val algorithm = PlatformDependantRandom(this)
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Randomizer = this

    override suspend fun random(size: Int): Buffer {
        return WebCrypto.getRandomValues(ByteArray(size))
    }

    override suspend fun random(output: Buffer): Buffer {
        return WebCrypto.getRandomValues(output)
    }

    override fun randomBlocking(size: Int): Buffer {
        return WebCrypto.getRandomValues(ByteArray(size))
    }

    override fun randomBlocking(output: Buffer): Buffer {
        return WebCrypto.getRandomValues(output)
    }

    override fun randomInstance(): Random {
        TODO("Not yet implemented")
    }
}
