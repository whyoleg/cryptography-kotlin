package dev.whyoleg.cryptography.random

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface RandomPrimitive : CryptographyPrimitive {
    public fun random(): BufferView
    public fun random(output: BufferView): BufferView

    public suspend fun randomSuspend(): BufferView
    public suspend fun randomSuspend(output: BufferView): BufferView
}
