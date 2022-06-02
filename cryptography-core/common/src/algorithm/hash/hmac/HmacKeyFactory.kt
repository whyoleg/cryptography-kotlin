package dev.whyoleg.cryptography.algorithm.hash.hmac

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public interface HmacKeyFactory<P> {
    public val async: Async<P>

    public val generate: KeyGenerate<Unit, HmacKey<P>>
    public val import: KeyImport<Unit, HmacKey<P>>

    public interface Async<P> {
        public suspend fun generate(keySize: BinarySize): HmacKey.Async<P>
        public suspend fun import(input: BufferView): HmacKey.Async<P>
    }
}
