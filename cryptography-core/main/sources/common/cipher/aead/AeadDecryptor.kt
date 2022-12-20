package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public typealias AeadDecryptorProvider<P> = CryptographyOperationProvider<P, AeadDecryptor>
public typealias AeadDecryptorFactory<P> = CryptographyOperationFactory<P, AeadDecryptor>

public interface AeadDecryptor : Decryptor {
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    override suspend fun decrypt(ciphertextInput: Buffer): Buffer = decrypt(null, ciphertextInput)
    override suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = decrypt(null, ciphertextInput, plaintextOutput)
    public fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer): Buffer
    public fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = decryptBlocking(null, ciphertextInput)
    override fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer =
        decryptBlocking(null, ciphertextInput, plaintextOutput)

    override fun decryptFunction(): AeadDecryptFunction
}
