package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.apple.internal.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Security.*

internal class CCDigest(
    private val state: AppleState,
    private val hashAlgorithm: CCHashAlgorithm,
) : Hasher, Digest {
    override fun hasher(): Hasher = this

    override val digestSize: Int get() = hashAlgorithm.digestSize

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun hashBlocking(dataInput: Buffer): Buffer {
        val output = ByteArray(digestSize)
        val result = hashAlgorithm.ccHash(
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
