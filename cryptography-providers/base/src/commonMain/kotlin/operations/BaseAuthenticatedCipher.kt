/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*

@CryptographyProviderApi
public interface BaseAuthenticatedCipher : AuthenticatedCipher, BaseCipher, BaseAuthenticatedEncryptor, BaseAuthenticatedDecryptor

@CryptographyProviderApi
public interface BaseAuthenticatedEncryptor : AuthenticatedEncryptor, BaseEncryptor {
    public fun createEncryptFunction(associatedData: ByteArray?): CipherFunction

    override fun createEncryptFunction(): CipherFunction {
        return createEncryptFunction(null)
    }

    override fun encryptBlocking(plaintext: ByteArray): ByteArray {
        return super<AuthenticatedEncryptor>.encryptBlocking(plaintext)
    }

    override fun encryptingSource(plaintext: RawSource): RawSource {
        return super<AuthenticatedEncryptor>.encryptingSource(plaintext)
    }

    override fun encryptingSink(ciphertext: RawSink): RawSink {
        return super<AuthenticatedEncryptor>.encryptingSink(ciphertext)
    }

    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return createEncryptFunction(associatedData).transform(plaintext)
    }

    override fun encryptingSource(plaintext: RawSource, associatedData: ByteArray?): RawSource {
        return createEncryptFunction(associatedData).transformedSource(plaintext)
    }

    override fun encryptingSink(ciphertext: RawSink, associatedData: ByteArray?): RawSink {
        return createEncryptFunction(associatedData).transformedSink(ciphertext)
    }
}

@CryptographyProviderApi
public interface BaseAuthenticatedDecryptor : AuthenticatedDecryptor, BaseDecryptor {
    public fun createDecryptFunction(associatedData: ByteArray?): CipherFunction

    override fun createDecryptFunction(): CipherFunction {
        return createDecryptFunction(null)
    }

    override fun decryptBlocking(ciphertext: ByteArray): ByteArray {
        return super<AuthenticatedDecryptor>.decryptBlocking(ciphertext)
    }

    override fun decryptingSource(ciphertext: RawSource): RawSource {
        return super<AuthenticatedDecryptor>.decryptingSource(ciphertext)
    }

    override fun decryptingSink(plaintext: RawSink): RawSink {
        return super<AuthenticatedDecryptor>.decryptingSink(plaintext)
    }

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return createDecryptFunction(associatedData).transform(ciphertext)
    }

    override fun decryptingSource(ciphertext: RawSource, associatedData: ByteArray?): RawSource {
        return createDecryptFunction(associatedData).transformedSource(ciphertext)
    }

    override fun decryptingSink(plaintext: RawSink, associatedData: ByteArray?): RawSink {
        return createDecryptFunction(associatedData).transformedSink(plaintext)
    }
}
