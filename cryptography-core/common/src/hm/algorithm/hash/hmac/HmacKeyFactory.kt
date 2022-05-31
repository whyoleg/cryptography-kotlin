package dev.whyoleg.cryptography.hm.algorithm.hash.hmac

import dev.whyoleg.vio.*

public interface HmacKeyFactory<P> {
    public val async: Async<P>

    public fun generate(keySize: BinarySize): HmacKey<P>
    public fun import(input: BufferView): HmacKey<P>

    public interface Async<P> {
        public suspend fun generate(keySize: BinarySize): HmacKey.Async<P>
        public suspend fun import(input: BufferView): HmacKey.Async<P>
    }
}