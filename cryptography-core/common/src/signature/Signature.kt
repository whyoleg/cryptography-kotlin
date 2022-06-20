package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*

public interface Signature : CryptographyPrimitive, Signer, Verifier {
    public interface Sync : Signature, Signer.Sync, Verifier.Sync
    public interface Async : Signature, Signer.Async, Verifier.Async
    public interface Stream : Signature, Signer.Stream, Verifier.Stream
}
