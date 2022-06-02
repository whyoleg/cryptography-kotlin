package dev.whyoleg.cryptography.algorithm.hash.hmac

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.operation.*

public interface HmacKey<P> : SecretKey {
    public val async: Async<P>

    public val mac: MacOperation<P>
    public val verify: VerifyOperation<P>
    public val export: KeyExport<Unit>

    public interface Async<P> {
        public val mac: MacOperation<P> //TODO
        public val export: AsyncKeyExport<Unit>
    }
}
