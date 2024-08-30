/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import kotlin.jvm.*

@Suppress("DEPRECATION_ERROR")
@Deprecated(
    "Replaced by BinarySize as wrapper class is not needed",
    ReplaceWith("BinarySize", "dev.whyoleg.cryptography.BinarySize"),
    DeprecationLevel.ERROR
)
@JvmInline
public value class SymmetricKeySize
@Deprecated(
    "Replaced by BinarySize as wrapper class is not needed",
    ReplaceWith("value"),
    DeprecationLevel.ERROR
)
constructor(public val value: BinarySize) {
    @Deprecated(
        "Replaced by AES.Key.Size as it's not really needed outside of AES",
        ReplaceWith("AES.Key.Size", "dev.whyoleg.cryptography.algorithms.symmetric.AES"),
        DeprecationLevel.ERROR
    )
    public companion object {
        public val B128: SymmetricKeySize get() = SymmetricKeySize(128.bits)
        public val B192: SymmetricKeySize get() = SymmetricKeySize(192.bits)
        public val B256: SymmetricKeySize get() = SymmetricKeySize(256.bits)
    }
}
