package dev.whyoleg.cryptography.jdk.internal

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.random.*
import java.security.*
import kotlin.random.*

internal val DefaultSecureRandom: SecureRandom = SecureRandom()

internal class JdkRandomProvider(
    private val state: JdkCryptographyState,
) : RandomizerProvider<CryptographyOperationParameters.Empty>(), Randomizer {
    override fun provideOperation(parameters: CryptographyOperationParameters.Empty): Randomizer = this

    override fun randomBlocking(size: Int): Buffer {
        return ByteArray(size).also(DefaultSecureRandom::nextBytes)
    }

    override fun randomBlocking(output: Buffer): Buffer {
        return output.also(DefaultSecureRandom::nextBytes)
    }

    override suspend fun random(size: Int): Buffer {
        return state.execute { randomBlocking(size) }
    }

    override suspend fun random(output: Buffer): Buffer {
        return state.execute { randomBlocking(output) }
    }

    override fun randomInstance(): Random {
        return DefaultSecureRandom.asKotlinRandom()
    }
}
