/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal sealed class CCHashAlgorithm {
    abstract val digestSize: Int
    abstract fun ccHash(
        data: CValuesRef<ByteVar>,
        dataLength: CC_LONG,
        digest: CValuesRef<UByteVar>,
    ): CPointer<UByteVar>?

    object SHA1 : CCHashAlgorithm() {
        override val digestSize: Int get() = CC_SHA1_DIGEST_LENGTH
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA1(data, dataLength, digest)
    }

    object SHA224 : CCHashAlgorithm() {
        override val digestSize: Int get() = CC_SHA224_DIGEST_LENGTH
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA224(data, dataLength, digest)
    }

    object SHA256 : CCHashAlgorithm() {
        override val digestSize: Int get() = CC_SHA256_DIGEST_LENGTH
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA256(data, dataLength, digest)
    }

    object SHA384 : CCHashAlgorithm() {
        override val digestSize: Int get() = CC_SHA384_DIGEST_LENGTH
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA384(data, dataLength, digest)
    }

    object SHA512 : CCHashAlgorithm() {
        override val digestSize: Int get() = CC_SHA512_DIGEST_LENGTH
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_SHA512(data, dataLength, digest)
    }

    object MD5 : CCHashAlgorithm() {
        override val digestSize: Int get() = CC_MD5_DIGEST_LENGTH
        override fun ccHash(
            data: CValuesRef<ByteVar>,
            dataLength: CC_LONG,
            digest: CValuesRef<UByteVar>,
        ): CPointer<UByteVar>? = CC_MD5(data, dataLength, digest)
    }
}
