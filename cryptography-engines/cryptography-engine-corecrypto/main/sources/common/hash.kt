package dev.whyoleg.cryptography.corecrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.io.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object Sha512 : HashAlgorithm() {
    override fun syncHasher(parameters: CryptographyParameters.Empty): SyncHasher = CCHasher.SHA512

    override fun asyncHasher(parameters: CryptographyParameters.Empty): AsyncHasher {
        TODO("Not yet implemented")
    }

    override fun hashFunction(parameters: CryptographyParameters.Empty): HashFunction {
        TODO("Not yet implemented")
    }
}

internal abstract class CCHasher : SyncHasher {
    object SHA512 : CCHasher() {
        override fun ccHash(data: CValuesRef<ByteVar>, dataLength: CC_LONG, digest: CValuesRef<UByteVar>): CPointer<UByteVar>? {
            return CC_SHA512(data, dataLength, digest)
        }
    }

    override val digestSize: Int
        get() = TODO("Not yet implemented")

    protected abstract fun ccHash(
        data: CValuesRef<ByteVar>,
        dataLength: CC_LONG,
        digest: CValuesRef<UByteVar>,
    ): CPointer<UByteVar>?

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun hash(dataInput: Buffer): Buffer {
        val output = ByteArray(digestSize)
        val result = ccHash(
            dataInput.refTo(0),
            dataInput.size.convert(),
            output.asUByteArray().refTo(0)
        )
//        if (result != kCCSuccess) throw Exception("CC_SHA512 failed")
        return output
    }

    override fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }
}
