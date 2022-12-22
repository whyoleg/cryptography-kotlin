@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.cipher.aead

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*

public typealias AeadBoxEncryptorProvider<P, B> = CryptographyOperationProvider<P, AeadBoxEncryptor<B>>
public typealias AeadBoxEncryptorFactory<P, B> = CryptographyOperationFactory<P, AeadBoxEncryptor<B>>

public interface AeadBoxEncryptor<B> : BoxEncryptor<B>, AeadEncryptor {
    public suspend fun encryptBox(associatedData: Buffer?, plaintextInput: Buffer): B
    public suspend fun encryptBox(associatedData: Buffer?, plaintextInput: Buffer, boxOutput: B): B
    public fun encryptBoxBlocking(associatedData: Buffer?, plaintextInput: Buffer): B
    public fun encryptBoxBlocking(associatedData: Buffer?, plaintextInput: Buffer, boxOutput: B): B

    override suspend fun encryptBox(plaintextInput: Buffer): B = encryptBox(null, plaintextInput)
    override suspend fun encryptBox(plaintextInput: Buffer, boxOutput: B): B = encryptBox(null, plaintextInput, boxOutput)
    override fun encryptBoxBlocking(plaintextInput: Buffer): B = encryptBoxBlocking(null, plaintextInput)
    override fun encryptBoxBlocking(plaintextInput: Buffer, boxOutput: B): B = encryptBoxBlocking(null, plaintextInput, boxOutput)
}
