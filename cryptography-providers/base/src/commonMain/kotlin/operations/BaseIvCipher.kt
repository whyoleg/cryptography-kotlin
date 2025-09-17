/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*

@CryptographyProviderApi
public interface BaseIvCipher : IvCipher, BaseCipher, BaseIvEncryptor, BaseIvDecryptor

@CryptographyProviderApi
public interface BaseIvEncryptor : IvEncryptor, BaseEncryptor {

    public fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction

    @DelicateCryptographyApi
    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return createEncryptFunctionWithIv(iv).transform(plaintext)
    }

    @DelicateCryptographyApi
    override fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink {
        return createEncryptFunctionWithIv(iv).transformedSink(ciphertext)
    }

    @DelicateCryptographyApi
    override fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource {
        return createEncryptFunctionWithIv(iv).transformedSource(plaintext)
    }
}

@CryptographyProviderApi
public interface BaseIvDecryptor : IvDecryptor, BaseDecryptor {

    public fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction

    @DelicateCryptographyApi
    override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        return createDecryptFunctionWithIv(iv).transform(ciphertext)
    }

    @DelicateCryptographyApi
    override fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource {
        return createDecryptFunctionWithIv(iv).transformedSource(ciphertext)
    }

    @DelicateCryptographyApi
    override fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink {
        return createDecryptFunctionWithIv(iv).transformedSink(plaintext)
    }
}
