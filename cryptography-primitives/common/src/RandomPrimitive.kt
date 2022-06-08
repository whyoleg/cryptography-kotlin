package dev.whyoleg.cryptography.primitives

import dev.whyoleg.vio.*

public interface RandomPrimitive {
    public fun random(): BufferView
    public fun random(output: BufferView): BufferView
}
