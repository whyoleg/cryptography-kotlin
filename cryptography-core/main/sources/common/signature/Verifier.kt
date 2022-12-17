package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*

public interface Verifier {
    public val signatureSize: Int
}

public interface SyncVerifier : Verifier {
    public fun verify(signatureInput: Buffer): Boolean
}

public interface AsyncVerifier : Verifier {
    public suspend fun verify(signatureInput: Buffer): Boolean
}

