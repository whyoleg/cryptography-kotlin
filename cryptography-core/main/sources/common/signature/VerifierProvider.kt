package dev.whyoleg.cryptography.signature

public interface VerifierProvider<P> {
    public val defaultVerifyParameters: P
    public fun syncVerifier(parameters: P = defaultVerifyParameters): SyncVerifier
    public fun asyncVerifier(parameters: P = defaultVerifyParameters): AsyncVerifier
    public fun verifyFunction(parameters: P = defaultVerifyParameters): VerifyFunction
}
