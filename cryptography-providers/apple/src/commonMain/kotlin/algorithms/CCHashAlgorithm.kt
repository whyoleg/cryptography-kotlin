/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal abstract class CCHashAlgorithm<CTX : CPointed> {
    abstract val digestSize: Int

    abstract fun alloc(): CPointer<CTX>
    abstract fun ccInit(context: CPointer<CTX>): Int
    abstract fun ccFinal(context: CPointer<CTX>, digest: CValuesRef<UByteVar>): Int
    abstract fun ccUpdate(context: CPointer<CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int

    object SHA1 : CCHashAlgorithm<CC_SHA1_CTX>() {
        override val digestSize: Int get() = CC_SHA1_DIGEST_LENGTH
        override fun alloc(): CPointer<CC_SHA1_CTX> = nativeHeap.alloc<CC_SHA1_CTX>().ptr
        override fun ccInit(context: CPointer<CC_SHA1_CTX>): Int = CC_SHA1_Init(context)
        override fun ccFinal(context: CPointer<CC_SHA1_CTX>, digest: CValuesRef<UByteVar>): Int = CC_SHA1_Final(digest, context)
        override fun ccUpdate(context: CPointer<CC_SHA1_CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int =
            CC_SHA1_Update(context, data, dataLength)
    }

    object SHA224 : CCHashAlgorithm<CC_SHA256_CTX>() {
        override val digestSize: Int get() = CC_SHA224_DIGEST_LENGTH
        override fun alloc(): CPointer<CC_SHA256_CTX> = nativeHeap.alloc<CC_SHA256_CTX>().ptr
        override fun ccInit(context: CPointer<CC_SHA256_CTX>): Int = CC_SHA224_Init(context)
        override fun ccFinal(context: CPointer<CC_SHA256_CTX>, digest: CValuesRef<UByteVar>): Int = CC_SHA224_Final(digest, context)
        override fun ccUpdate(context: CPointer<CC_SHA256_CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int =
            CC_SHA224_Update(context, data, dataLength)
    }

    object SHA256 : CCHashAlgorithm<CC_SHA256_CTX>() {
        override val digestSize: Int get() = CC_SHA256_DIGEST_LENGTH
        override fun alloc(): CPointer<CC_SHA256_CTX> = nativeHeap.alloc<CC_SHA256_CTX>().ptr
        override fun ccInit(context: CPointer<CC_SHA256_CTX>): Int = CC_SHA256_Init(context)
        override fun ccFinal(context: CPointer<CC_SHA256_CTX>, digest: CValuesRef<UByteVar>): Int = CC_SHA256_Final(digest, context)
        override fun ccUpdate(context: CPointer<CC_SHA256_CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int =
            CC_SHA256_Update(context, data, dataLength)
    }

    object SHA384 : CCHashAlgorithm<CC_SHA512_CTX>() {
        override val digestSize: Int get() = CC_SHA384_DIGEST_LENGTH
        override fun alloc(): CPointer<CC_SHA512_CTX> = nativeHeap.alloc<CC_SHA512_CTX>().ptr
        override fun ccInit(context: CPointer<CC_SHA512_CTX>): Int = CC_SHA384_Init(context)
        override fun ccFinal(context: CPointer<CC_SHA512_CTX>, digest: CValuesRef<UByteVar>): Int = CC_SHA384_Final(digest, context)
        override fun ccUpdate(context: CPointer<CC_SHA512_CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int =
            CC_SHA384_Update(context, data, dataLength)
    }

    object SHA512 : CCHashAlgorithm<CC_SHA512_CTX>() {
        override val digestSize: Int get() = CC_SHA512_DIGEST_LENGTH
        override fun alloc(): CPointer<CC_SHA512_CTX> = nativeHeap.alloc<CC_SHA512_CTX>().ptr
        override fun ccInit(context: CPointer<CC_SHA512_CTX>): Int = CC_SHA512_Init(context)
        override fun ccFinal(context: CPointer<CC_SHA512_CTX>, digest: CValuesRef<UByteVar>): Int = CC_SHA512_Final(digest, context)
        override fun ccUpdate(context: CPointer<CC_SHA512_CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int =
            CC_SHA512_Update(context, data, dataLength)
    }

    object MD5 : CCHashAlgorithm<CC_MD5_CTX>() {
        override val digestSize: Int get() = CC_MD5_DIGEST_LENGTH
        override fun alloc(): CPointer<CC_MD5_CTX> = nativeHeap.alloc<CC_MD5_CTX>().ptr
        override fun ccInit(context: CPointer<CC_MD5_CTX>): Int = CC_MD5_Init(context)
        override fun ccFinal(context: CPointer<CC_MD5_CTX>, digest: CValuesRef<UByteVar>): Int = CC_MD5_Final(digest, context)
        override fun ccUpdate(context: CPointer<CC_MD5_CTX>, data: CValuesRef<ByteVar>, dataLength: CC_LONG): Int =
            CC_MD5_Update(context, data, dataLength)
    }
}
