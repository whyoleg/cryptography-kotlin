/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import java.security.*

internal object JdkShake256 : XOF {
    fun isSupported(provider: Provider?): Boolean = BouncyCastleBridge.supportsShake256(provider)

    override val id: CryptographyAlgorithmId<XOF> get() = SHAKE256

    override fun hasher(outputSize: BinarySize): Hasher {
        require(outputSize.inBytes > 0) { "Output size must be greater than 0" }
        return Shake256Hasher(outputSize.inBytes)
    }

    private class Shake256Hasher(private val outputSizeBytes: Int) : Hasher {
        override fun createHashFunction(): HashFunction = Shake256HashFunction(outputSizeBytes)
    }

    private class Shake256HashFunction(private val outputSizeBytes: Int) : HashFunction {
        private var state: BouncyCastleBridge.Shake256State? = BouncyCastleBridge.Shake256State()

        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)
            state().update(source, startIndex, endIndex - startIndex)
        }

        override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            checkBounds(destination.size, destinationOffset, destinationOffset + outputSizeBytes)
            return state().finish(destination, destinationOffset, outputSizeBytes)
        }

        override fun hashToByteArray(): ByteArray {
            val output = ByteArray(outputSizeBytes)
            check(hashIntoByteArray(output) == outputSizeBytes)
            return output
        }
        override fun reset(): Unit = state().reset()

        override fun close() {
            state = null
        }

        private fun state(): BouncyCastleBridge.Shake256State = checkNotNull(state) { "Already closed" }
    }
}
