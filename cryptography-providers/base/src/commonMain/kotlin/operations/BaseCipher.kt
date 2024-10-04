/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*

@CryptographyProviderApi
public interface BaseCipher : Cipher, BaseEncryptor, BaseDecryptor

@CryptographyProviderApi
public interface BaseEncryptor : Encryptor {
    public fun createEncryptFunction(): CipherFunction

    override fun encryptBlocking(plaintext: ByteArray): ByteArray {
        return createEncryptFunction().transform(plaintext)
    }

    override fun encryptingSource(plaintext: RawSource): RawSource {
        return createEncryptFunction().transformedSource(plaintext)
    }

    override fun encryptingSink(ciphertext: RawSink): RawSink {
        return createEncryptFunction().transformedSink(ciphertext)
    }
}

@CryptographyProviderApi
public interface BaseDecryptor : Decryptor {
    public fun createDecryptFunction(): CipherFunction

    override fun decryptBlocking(ciphertext: ByteArray): ByteArray {
        return createDecryptFunction().transform(ciphertext)
    }

    override fun decryptingSource(ciphertext: RawSource): RawSource {
        return createDecryptFunction().transformedSource(ciphertext)
    }

    override fun decryptingSink(plaintext: RawSink): RawSink {
        return createDecryptFunction().transformedSink(plaintext)
    }
}
