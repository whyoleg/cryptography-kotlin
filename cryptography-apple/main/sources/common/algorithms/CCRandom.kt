package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.io.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.random.*

internal class CCRandom(
    private val state: AppleState,
) : PlatformDependantRandom {

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
