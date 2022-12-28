@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*

public typealias DecryptorProvider<P> = CryptographyOperationProvider<P, Decryptor>
public typealias DecryptorFactory<P> = CryptographyOperationFactory<P, Decryptor>

public interface Decryptor : CryptographyOperation {
    public fun plaintextSize(ciphertextSize: Int): Int
    public suspend fun decrypt(ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    public fun decryptBlocking(ciphertextInput: Buffer): Buffer
    public fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
}
