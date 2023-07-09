/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import kotlinx.cinterop.*

private val almostEmptyArray = ByteArray(1)

//this hack will be dropped with introducing of new IO or functions APIs
internal fun ByteArray.fixEmpty(): ByteArray = if (isNotEmpty()) this else almostEmptyArray

internal fun ByteArray.refToFixed(index: Int): CValuesRef<ByteVar> {
    if (index == size) return almostEmptyArray.refTo(0)
    return refTo(index)
}
