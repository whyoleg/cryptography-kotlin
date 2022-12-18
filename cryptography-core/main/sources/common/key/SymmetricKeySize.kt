package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import kotlin.jvm.*

//TODO: or SecretKeySize?
@JvmInline
public value class SymmetricKeySize(public val value: BinarySize) {
    public companion object {
        public val B128: SymmetricKeySize get() = SymmetricKeySize(128.bytes)
        public val B192: SymmetricKeySize get() = SymmetricKeySize(192.bytes)
        public val B256: SymmetricKeySize get() = SymmetricKeySize(256.bytes)
    }
}
