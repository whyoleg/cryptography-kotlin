/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

internal actual inline fun ByteArray.useAsInt8Array(block: (array: Int8Array) -> Unit) {
    block(this.unsafeCast<Int8Array>())
}
