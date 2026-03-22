/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

/**
 * Combines [Encryptor] and [Decryptor] for encryption and decryption operations.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Cipher : Encryptor, Decryptor

/**
 * Encrypts plaintext data to ciphertext.
 *
 * Provides [suspend][encrypt], [blocking][encryptBlocking], and [streaming][encryptingSource] variants.
 *
 * For the decryption counterpart, see [Decryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    /**
     * Encrypts the given [plaintext] and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptBlocking] when calling from non-suspending code.
     */
    public suspend fun encrypt(plaintext: ByteArray): ByteArray {
        return encryptBlocking(plaintext)
    }

    /**
     * Encrypts the given [plaintext] and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptBlocking] when calling from non-suspending code.
     */
    public suspend fun encrypt(plaintext: ByteString): ByteString {
        return encrypt(plaintext.asByteArray()).asByteString()
    }

    /**
     * Encrypts the given [plaintext] and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encrypt] when calling from suspending code.
     */
    public fun encryptBlocking(plaintext: ByteArray): ByteArray

    /**
     * Encrypts the given [plaintext] and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encrypt] when calling from suspending code.
     */
    public fun encryptBlocking(plaintext: ByteString): ByteString {
        return encryptBlocking(plaintext.asByteArray()).asByteString()
    }

    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source.
     * The resulting source produces ciphertext on reads.
     *
     * Use [encryptingSink] to wrap a sink instead.
     */
    public fun encryptingSource(plaintext: RawSource): RawSource

    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext to [ciphertext].
     * Write plaintext to the returned sink, and ciphertext will be forwarded to [ciphertext].
     *
     * Use [encryptingSource] to wrap a source instead.
     */
    public fun encryptingSink(ciphertext: RawSink): RawSink
}

/**
 * Decrypts ciphertext data to plaintext.
 *
 * Provides [suspend][decrypt], [blocking][decryptBlocking], and [streaming][decryptingSource] variants.
 *
 * For the encryption counterpart, see [Encryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    /**
     * Decrypts the given [ciphertext] and returns the resulting plaintext as a [ByteArray].
     *
     * Use [decryptBlocking] when calling from non-suspending code.
     */
    public suspend fun decrypt(ciphertext: ByteArray): ByteArray {
        return decryptBlocking(ciphertext)
    }

    /**
     * Decrypts the given [ciphertext] and returns the resulting plaintext as a [ByteString].
     *
     * Use [decryptBlocking] when calling from non-suspending code.
     */
    public suspend fun decrypt(ciphertext: ByteString): ByteString {
        return decrypt(ciphertext.asByteArray()).asByteString()
    }

    /**
     * Decrypts the given [ciphertext] and returns the resulting plaintext as a [ByteArray].
     *
     * Use [decrypt] when calling from suspending code.
     */
    public fun decryptBlocking(ciphertext: ByteArray): ByteArray

    /**
     * Decrypts the given [ciphertext] and returns the resulting plaintext as a [ByteString].
     *
     * Use [decrypt] when calling from suspending code.
     */
    public fun decryptBlocking(ciphertext: ByteString): ByteString {
        return decryptBlocking(ciphertext.asByteArray()).asByteString()
    }

    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source.
     * The resulting source produces plaintext on reads.
     *
     * Use [decryptingSink] to wrap a sink instead.
     */
    public fun decryptingSource(ciphertext: RawSource): RawSource

    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext to [plaintext].
     * Write ciphertext to the returned sink, and plaintext will be forwarded to [plaintext].
     *
     * Use [decryptingSource] to wrap a source instead.
     */
    public fun decryptingSink(plaintext: RawSink): RawSink
}
