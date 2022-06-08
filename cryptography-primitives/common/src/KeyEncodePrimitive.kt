package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public interface KeyEncodePrimitive<F : KeyFormat> {
    public fun encode(format: F): BufferView
    public fun encode(format: F, output: BufferView): BufferView
}
