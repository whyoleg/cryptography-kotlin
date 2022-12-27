@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.operations.*

public typealias SignatureProvider<P> = CryptographyOperationProvider<P, Signature>
public typealias SignatureFactory<P> = CryptographyOperationFactory<P, Signature>

//TODO: decide on other name or just make it `MAC`?
public interface Signature : SignatureGenerator, SignatureVerifier
