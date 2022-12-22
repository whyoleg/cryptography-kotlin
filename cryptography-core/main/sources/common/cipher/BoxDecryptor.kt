package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.io.*

public typealias BoxDecryptorProvider<P, B> = CryptographyOperationProvider<P, BoxDecryptor<B>>
public typealias BoxDecryptorFactory<P, B> = CryptographyOperationFactory<P, BoxDecryptor<B>>

public interface BoxDecryptor<B> : Encryptor {
    public suspend fun decryptBox(boxInput: B): Buffer
    public suspend fun decryptBox(boxInput: B, plaintextOutput: Buffer): Buffer
    public fun decryptBoxBlocking(boxInput: B): Buffer
    public fun decryptBoxBlocking(boxInput: B, plaintextOutput: Buffer): Buffer
}
