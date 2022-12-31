package dev.whyoleg.cryptography.apple.internal

import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal sealed class CCHashAlgorithm {
    abstract fun ccHash(
        data: CValuesRef<ByteVar>,
        dataLength: CC_LONG,
        digest: CValuesRef<UByteVar>,
    ): CPointer<UByteVar>?

    object SHA512 : CCHashAlgorithm() {
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA512(data, dataLength, digest)
    }

    object SHA1 : CCHashAlgorithm() {
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA1(data, dataLength, digest)
    }

    object MD5 : CCHashAlgorithm() {
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_MD5(data, dataLength, digest)
    }
}
