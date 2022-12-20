package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public typealias CipherFactory<P> = CryptographyOperationFactory<P, Cipher>
public typealias CipherProvider<P> = CryptographyOperationProvider<P, Cipher>

public interface Cipher : Encryptor, Decryptor
