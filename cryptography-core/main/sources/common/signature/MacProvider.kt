package dev.whyoleg.cryptography.signature

public interface MacProvider<P> : SignerProvider<P>, VerifierProvider<P> {
    public val defaultMacParameters: P
    override val defaultSignParameters: P get() = defaultMacParameters
    override val defaultVerifyParameters: P get() = defaultMacParameters
    public fun syncMac(parameters: P = defaultMacParameters): SyncMac
    public fun asyncMac(parameters: P = defaultMacParameters): AsyncMac
}
