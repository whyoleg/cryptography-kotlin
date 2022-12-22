@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias EncryptorProvider<P> = CryptographyOperationProvider<P, Encryptor>
public typealias EncryptorFactory<P> = CryptographyOperationFactory<P, Encryptor>

public interface Encryptor : CryptographyOperation {
    public fun ciphertextSize(plaintextSize: Int): Int
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    public fun encryptBlocking(plaintextInput: Buffer): Buffer
    public fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    public fun encryptFunction(): EncryptFunction
}
