package dev.whyoleg.cryptography.operations.cipher.aead

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*

public typealias AeadCipherFactory<P> = CryptographyOperationFactory<P, AeadCipher>
public typealias AeadCipherProvider<P> = CryptographyOperationProvider<P, AeadCipher>

public interface AeadCipher : Cipher, AeadEncryptor, AeadDecryptor

