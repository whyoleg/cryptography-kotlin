/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*

@CryptographyProviderApi
public interface BaseIvAuthenticatedCipher : IvAuthenticatedCipher,
    BaseAuthenticatedCipher,
    BaseIvAuthenticatedEncryptor,
    BaseIvAuthenticatedDecryptor

@CryptographyProviderApi
public interface BaseIvAuthenticatedEncryptor : IvAuthenticatedEncryptor, BaseAuthenticatedEncryptor {

    public fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction

    @DelicateCryptographyApi
    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return createEncryptFunctionWithIv(iv, associatedData).transform(plaintext)
    }

    @DelicateCryptographyApi
    override fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource {
        return createEncryptFunctionWithIv(iv, associatedData).transformedSource(plaintext)
    }

    @DelicateCryptographyApi
    override fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink {
        return createEncryptFunctionWithIv(iv, associatedData).transformedSink(ciphertext)
    }
}

@CryptographyProviderApi
public interface BaseIvAuthenticatedDecryptor : IvAuthenticatedDecryptor, BaseAuthenticatedDecryptor {

    public fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction

    @DelicateCryptographyApi
    override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return createDecryptFunctionWithIv(iv, associatedData).transform(ciphertext)
    }

    @DelicateCryptographyApi
    override fun decryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource {
        return createDecryptFunctionWithIv(iv, associatedData).transformedSource(plaintext)
    }

    @DelicateCryptographyApi
    override fun decryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink {
        return createDecryptFunctionWithIv(iv, associatedData).transformedSink(ciphertext)
    }
}
