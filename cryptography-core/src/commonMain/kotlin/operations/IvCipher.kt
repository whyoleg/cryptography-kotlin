/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvCipher : Cipher, IvEncryptor, IvDecryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvEncryptor : Encryptor {
    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return encryptWithIvBlocking(iv, plaintext)
    }

    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString): ByteString {
        return encryptWithIv(iv.asByteArray(), plaintext.asByteArray()).asByteString()
    }

    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray

    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString): ByteString {
        return encryptWithIvBlocking(iv.asByteArray(), plaintext.asByteArray()).asByteString()
    }


    @DelicateCryptographyApi
    public fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource

    @DelicateCryptographyApi
    public fun encryptingSourceWithIv(iv: ByteString, plaintext: RawSource): RawSource {
        return encryptingSourceWithIv(iv.asByteArray(), plaintext)
    }


    @DelicateCryptographyApi
    public fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink

    @DelicateCryptographyApi
    public fun encryptingSinkWithIv(iv: ByteString, ciphertext: RawSink): RawSink {
        return encryptingSinkWithIv(iv.asByteArray(), ciphertext)
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvDecryptor : Decryptor {
    @DelicateCryptographyApi
    public suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        return decryptWithIvBlocking(iv, ciphertext)
    }

    @DelicateCryptographyApi
    public suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString): ByteString {
        return decryptWithIv(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
    }

    @DelicateCryptographyApi
    public fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray

    @DelicateCryptographyApi
    public fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString): ByteString {
        return decryptWithIvBlocking(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
    }


    @DelicateCryptographyApi
    public fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource

    @DelicateCryptographyApi
    public fun decryptingSourceWithIv(iv: ByteString, ciphertext: RawSource): RawSource {
        return decryptingSourceWithIv(iv.asByteArray(), ciphertext)
    }


    @DelicateCryptographyApi
    public fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink

    @DelicateCryptographyApi
    public fun decryptingSinkWithIv(iv: ByteString, plaintext: RawSink): RawSink {
        return decryptingSinkWithIv(iv.asByteArray(), plaintext)
    }
}
