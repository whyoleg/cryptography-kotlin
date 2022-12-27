@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias KeyDerivationProvider<P> = CryptographyOperationProvider<P, KeyDerivation>
public typealias KeyDerivationFactory<P> = CryptographyOperationFactory<P, KeyDerivation>

public interface KeyDerivation : CryptographyOperation {
    //TODO: decide on name
    // add length parameter?
    public suspend fun deriveKeyFrom(dataInput: Buffer): Buffer
    public suspend fun deriveKeyFrom(dataInput: Buffer, keyOutput: Buffer): Buffer
    public fun deriveKeyFromBlocking(dataInput: Buffer): Buffer
    public fun deriveKeyFromBlocking(dataInput: Buffer, keyOutput: Buffer): Buffer
}
