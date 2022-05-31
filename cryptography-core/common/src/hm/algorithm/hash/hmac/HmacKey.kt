package dev.whyoleg.cryptography.hm.algorithm.hash.hmac

import dev.whyoleg.cryptography.hm.mac.*
import dev.whyoleg.vio.*

public interface HmacKey<P> {
    public val async: Async<P>

    public val mac: MacPrimitive<P>

    public fun export(output: BufferView)
    public fun export(): BufferView

    public interface Async<P> {
        public val mac: MacPrimitive.Async<P>

        public suspend fun export(output: BufferView)
        public suspend fun export(): BufferView
    }
}
