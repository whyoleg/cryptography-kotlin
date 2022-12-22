package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.operations.*

public typealias SignatureProvider<P> = CryptographyOperationProvider<P, Signature>
public typealias SignatureFactory<P> = CryptographyOperationFactory<P, Signature>

public interface Signature : Signer, Verifier
