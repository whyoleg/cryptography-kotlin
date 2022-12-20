package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public typealias AeadCipherFactory<P> = CryptographyOperationFactory<P, AeadCipher>
public typealias AeadCipherProvider<P> = CryptographyOperationProvider<P, AeadCipher>

public interface AeadCipher : Cipher, AeadEncryptor, AeadDecryptor
