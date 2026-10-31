/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

// f.e. WebCrypto doesn't support incremental functions
data class CreateFunctionTestOperation(val function: String) : TestOperation

// all providers fail when creating functions
fun TestLimitationScope.failsIfIncrementalFunctionsUnsupported(): TestLimitation? = when {
    provider.isWebCrypto -> fails("Incremental functions are not supported")
    else                 -> null
}

// different ways to feed the same data into `UpdateFunction`
internal val updateFunctionVariants: List<UpdateFunction.(ByteString) -> Unit> = listOf(
    { update(it) },
    { updateChunked(it, chunks = 10) },
    { viaUpdatingSource(it) },
    { viaUpdatingSink(it) },
)

internal fun UpdateFunction.updateChunked(data: ByteString, chunks: Int) {
    var step = data.size / chunks
    if (step == 0) step = data.size
    var start = 0
    while (start < data.size) {
        update(data, start, minOf(data.size, start + step))
        start += step
    }
}

internal fun UpdateFunction.viaUpdatingSource(data: ByteString) {
    updatingSource(Buffer(data).bufferedSource()).buffered().use {
        assertBytesEquals(data, it.readByteString()) { "UpdateFunction.viaUpdatingSource" }
    }
}

internal fun UpdateFunction.viaUpdatingSink(data: ByteString) {
    val output = Buffer()
    updatingSink(output.bufferedSink()).buffered().use {
        it.write(data)
    }
    assertBytesEquals(data, output.readByteString()) { "UpdateFunction.viaUpdatingSink" }
}
