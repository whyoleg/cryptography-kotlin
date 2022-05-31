package dev.whyoleg.cryptography.hm.key

public interface KeyExport<P> {
    public val async: Async<P>

    public operator fun invoke(keyStore: KeyStore, parameters: P)

    public interface Async<P> {
        public suspend operator fun invoke(keyStore: KeyStore, parameters: P)
    }
}

