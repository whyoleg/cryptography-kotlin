/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlin.wasm.*
import kotlin.wasm.unsafe.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = WasiPreview1CryptographyRandom

private object WasiPreview1CryptographyRandom : AbstractRandom() {
    @OptIn(UnsafeWasmMemoryApi::class)
    override fun fillBytes(array: ByteArray) {
        val size = array.size
        withScopedMemoryAllocator { allocator ->
            val pointer = allocator.allocate(size)
            val result = wasiRandomGet(pointer.address.toInt(), size)
            if (result != 0) error("wasi error code: $result")

            repeat(size) {
                array[it] = (pointer + it).loadByte()
            }
        }
    }
}

@WasmImport("wasi_snapshot_preview1", "random_get")
private external fun wasiRandomGet(address: Int, size: Int): Int
