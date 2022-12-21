package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*


public typealias AeadBoxCipherProvider<P, B> = CryptographyOperationProvider<P, AeadBoxCipher<B>>
public typealias AeadBoxCipherFactory<P, B> = CryptographyOperationFactory<P, AeadBoxCipher<B>>

public interface AeadBoxCipher<B> : AeadCipher, BoxCipher<B>, AeadBoxEncryptor<B>, AeadBoxDecryptor<B>
