package dev.whyoleg.cryptography.api

public interface Verifier {
    public val signatureSize: Int
}

public interface SyncVerifier : Verifier {
    public fun verify(signatureInput: Buffer): Boolean
}

public interface AsyncVerifier : Verifier {
    public suspend fun verify(signatureInput: Buffer): Boolean
}

public interface VerifyFunction : Closeable {
    public val signatureSize: Int

    public fun update(inputData: Buffer)

    public fun finish(inputData: Buffer): Boolean
}
