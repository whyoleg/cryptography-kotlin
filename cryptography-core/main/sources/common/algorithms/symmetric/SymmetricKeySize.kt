package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import kotlin.jvm.*

@JvmInline
public value class SymmetricKeySize(public val value: BinarySize) {
    public companion object {
        public val B128: SymmetricKeySize get() = SymmetricKeySize(128.bits)
        public val B192: SymmetricKeySize get() = SymmetricKeySize(192.bits)
        public val B256: SymmetricKeySize get() = SymmetricKeySize(256.bits)
    }
}
