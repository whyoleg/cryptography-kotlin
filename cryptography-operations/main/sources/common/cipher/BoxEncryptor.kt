package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias BoxEncryptorProvider<P, B> = CryptographyOperationProvider<P, BoxEncryptor<B>>
public typealias BoxEncryptorFactory<P, B> = CryptographyOperationFactory<P, BoxEncryptor<B>>

public interface BoxEncryptor<B> : Encryptor {
    public suspend fun encryptBox(plaintextInput: Buffer): B
    public suspend fun encryptBox(plaintextInput: Buffer, boxOutput: B): B
    public fun encryptBoxBlocking(plaintextInput: Buffer): B
    public fun encryptBoxBlocking(plaintextInput: Buffer, boxOutput: B): B
}
