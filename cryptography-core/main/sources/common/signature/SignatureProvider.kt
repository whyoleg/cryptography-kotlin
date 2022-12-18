package dev.whyoleg.cryptography.signature

public interface SignatureProvider<P> : SignerProvider<P>, VerifierProvider<P> {
    public val defaultSignatureParameters: P
    override val defaultSignParameters: P get() = defaultSignatureParameters
    override val defaultVerifyParameters: P get() = defaultSignatureParameters
    public fun syncSignature(parameters: P = defaultSignatureParameters): SyncSignature
    public fun asyncSignature(parameters: P = defaultSignatureParameters): AsyncSignature
    override fun syncSigner(parameters: P): SyncSigner = syncSignature(parameters)
    override fun asyncSigner(parameters: P): AsyncSigner = asyncSignature(parameters)
    override fun syncVerifier(parameters: P): SyncVerifier = syncSignature(parameters)
    override fun asyncVerifier(parameters: P): AsyncVerifier = asyncSignature(parameters)
}
