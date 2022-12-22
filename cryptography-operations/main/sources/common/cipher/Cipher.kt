@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.operations.*

public typealias CipherProvider<P> = CryptographyOperationProvider<P, Cipher>
public typealias CipherFactory<P> = CryptographyOperationFactory<P, Cipher>

public interface Cipher : Encryptor, Decryptor
