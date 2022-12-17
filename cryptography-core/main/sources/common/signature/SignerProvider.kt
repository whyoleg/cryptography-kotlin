package dev.whyoleg.cryptography.signature

public interface SignerProvider<P> {
    public val defaultSignParameters: P
    public fun syncSigner(parameters: P = defaultSignParameters): SyncSigner
    public fun asyncSigner(parameters: P = defaultSignParameters): AsyncSigner
    public fun signFunction(parameters: P = defaultSignParameters): SignFunction
}
