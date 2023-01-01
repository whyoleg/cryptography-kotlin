package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import kotlin.random.*

internal class JdkPlatformRandom(
    private val state: JdkCryptographyState,
) : PlatformDependantRandom {

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
