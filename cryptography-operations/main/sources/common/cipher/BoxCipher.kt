@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.operations.*

public typealias BoxCipherProvider<P, B> = CryptographyOperationProvider<P, BoxCipher<B>>
public typealias BoxCipherFactory<P, B> = CryptographyOperationFactory<P, BoxCipher<B>>

public interface BoxCipher<B> : Cipher, BoxEncryptor<B>, BoxDecryptor<B>
