package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.io.*

public typealias DecryptorProvider<P> = CryptographyOperationProvider<P, Decryptor>
public typealias DecryptorFactory<P> = CryptographyOperationFactory<P, Decryptor>

public interface Decryptor : CryptographyOperation {
    public fun plaintextSize(ciphertextSize: Int): Int
    public suspend fun decrypt(ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    public fun decryptBlocking(ciphertextInput: Buffer): Buffer
    public fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    public fun decryptFunction(): DecryptFunction
}
