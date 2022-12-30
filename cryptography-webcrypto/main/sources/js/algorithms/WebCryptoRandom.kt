package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.webcrypto.external.*
import kotlin.random.*

internal object WebCryptoRandom : PlatformDependantRandom {

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
