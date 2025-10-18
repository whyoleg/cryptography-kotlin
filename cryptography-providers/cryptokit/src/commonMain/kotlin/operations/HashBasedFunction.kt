/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import kotlinx.cinterop.*

@OptIn(UnsafeNumber::class)
internal abstract class HashBasedFunction(
    private val algorithm: DwcHashAlgorithm,
) : UpdateFunction {
    private var _function: DwcHashFunction? = DwcHashFunction(algorithm)

    protected val function: DwcHashFunction
        get() = _function ?: error("Hash function is closed")

    final override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        source.useNSData(startIndex, endIndex, function::doUpdate)
    }

    final override fun reset() {
        checkNotNull(_function) { "Hash function is closed" }
        _function = DwcHashFunction(algorithm)
    }

    final override fun close() {
        _function = null
    }
}
