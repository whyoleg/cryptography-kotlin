package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.io.*

public typealias BoxEncryptorProvider<P, B> = CryptographyOperationProvider<P, BoxEncryptor<B>>
public typealias BoxEncryptorFactory<P, B> = CryptographyOperationFactory<P, BoxEncryptor<B>>

public interface BoxEncryptor<B> : Encryptor {
    public suspend fun encryptBox(plaintextInput: Buffer): B
    public suspend fun encryptBox(plaintextInput: Buffer, boxOutput: B): B
    public fun encryptBoxBlocking(plaintextInput: Buffer): B
    public fun encryptBoxBlocking(plaintextInput: Buffer, boxOutput: B): B
}
