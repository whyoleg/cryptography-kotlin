package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public interface KeyEncodePrimitive<F : KeyFormat> {
    public fun encode(format: F): BufferView
    public fun encode(format: F, output: BufferView): BufferView
}

public interface KeyDecodePrimitive<F : KeyFormat, K : Key> {
    public fun decode(format: F, input: BufferView): K
}

public interface KeyGeneratePrimitive<K : Key> {
    public fun generate(): K
}
