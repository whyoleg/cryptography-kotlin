package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public typealias AeadBoxDecryptorProvider<P, B> = CryptographyOperationProvider<P, AeadBoxDecryptor<B>>
public typealias AeadBoxDecryptorFactory<P, B> = CryptographyOperationFactory<P, AeadBoxDecryptor<B>>

public interface AeadBoxDecryptor<B> : BoxDecryptor<B>, AeadDecryptor {
    public suspend fun decryptBox(associatedData: Buffer?, boxInput: B): Buffer
    public suspend fun decryptBox(associatedData: Buffer?, boxInput: B, plaintextOutput: Buffer): Buffer
    public fun decryptBoxBlocking(associatedData: Buffer?, boxInput: B): Buffer
    public fun decryptBoxBlocking(associatedData: Buffer?, boxInput: B, plaintextOutput: Buffer): Buffer

    override suspend fun decryptBox(boxInput: B): Buffer = decryptBox(null, boxInput)
    override suspend fun decryptBox(boxInput: B, plaintextOutput: Buffer): Buffer = decryptBox(null, boxInput, plaintextOutput)
    override fun decryptBoxBlocking(boxInput: B): Buffer = decryptBoxBlocking(null, boxInput)
    override fun decryptBoxBlocking(boxInput: B, plaintextOutput: Buffer): Buffer = decryptBoxBlocking(null, boxInput, plaintextOutput)
}
