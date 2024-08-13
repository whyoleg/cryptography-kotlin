/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.binary.BinarySize.Companion.bits
import kotlin.jvm.*

@JvmInline
public value class SymmetricKeySize(public val value: BinarySize) {
    public companion object {
        public val B128: SymmetricKeySize get() = SymmetricKeySize(128.bits)
        public val B192: SymmetricKeySize get() = SymmetricKeySize(192.bits)
        public val B256: SymmetricKeySize get() = SymmetricKeySize(256.bits)
    }
}
