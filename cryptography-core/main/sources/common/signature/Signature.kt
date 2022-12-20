package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.*

public typealias SignatureProvider<P> = CryptographyOperationProvider<P, Signature>
public typealias SignatureFactory<P> = CryptographyOperationFactory<P, Signature>

public interface Signature : Signer, Verifier
