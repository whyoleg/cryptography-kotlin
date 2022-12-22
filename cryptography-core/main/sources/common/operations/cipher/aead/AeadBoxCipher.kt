package dev.whyoleg.cryptography.operations.cipher.aead

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*


public typealias AeadBoxCipherProvider<P, B> = CryptographyOperationProvider<P, AeadBoxCipher<B>>
public typealias AeadBoxCipherFactory<P, B> = CryptographyOperationFactory<P, AeadBoxCipher<B>>

public interface AeadBoxCipher<B> : AeadCipher, BoxCipher<B>, AeadBoxEncryptor<B>, AeadBoxDecryptor<B>
