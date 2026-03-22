/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

/**
 * Combines [AuthenticatedEncryptor] and [AuthenticatedDecryptor] for authenticated encryption
 * with associated data (AEAD).
 *
 * The authentication tag is appended to the ciphertext:
 * encrypt returns `ciphertext || tag`, and decrypt expects `ciphertext || tag`.
 *
 * For IV support, see [IvAuthenticatedCipher].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedCipher : Cipher, AuthenticatedEncryptor, AuthenticatedDecryptor

/**
 * Encrypts plaintext with optional associated data for authenticated encryption (AEAD).
 * When associated data is provided, it is authenticated but not encrypted.
 * When associated data is `null`, only the plaintext is authenticated and encrypted.
 *
 * For the decryption counterpart, see [AuthenticatedDecryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    /**
     * Encrypts the given [plaintext] without associated data
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptBlocking] when calling from non-suspending code.
     */
    public override suspend fun encrypt(plaintext: ByteArray): ByteArray {
        return encrypt(plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] without associated data
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptBlocking] when calling from non-suspending code.
     */
    public override suspend fun encrypt(plaintext: ByteString): ByteString {
        return encrypt(plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptBlocking] when calling from non-suspending code.
     */
    public suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return encryptBlocking(plaintext, associatedData)
    }

    /**
     * Encrypts the given [plaintext] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptBlocking] when calling from non-suspending code.
     */
    public suspend fun encrypt(plaintext: ByteString, associatedData: ByteString?): ByteString {
        return encrypt(plaintext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    /**
     * Encrypts the given [plaintext] without associated data
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encrypt] when calling from suspending code.
     */
    public override fun encryptBlocking(plaintext: ByteArray): ByteArray {
        return encryptBlocking(plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] without associated data
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encrypt] when calling from suspending code.
     */
    public override fun encryptBlocking(plaintext: ByteString): ByteString {
        return encryptBlocking(plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encrypt] when calling from suspending code.
     */
    public fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    /**
     * Encrypts the given [plaintext] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encrypt] when calling from suspending code.
     */
    public fun encryptBlocking(plaintext: ByteString, associatedData: ByteString?): ByteString {
        return encryptBlocking(plaintext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * without associated data.
     *
     * Use [encryptingSink] to wrap a sink instead.
     */
    public override fun encryptingSource(plaintext: RawSource): RawSource {
        return encryptingSource(plaintext, null as ByteArray?)
    }

    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * with optional [associatedData].
     *
     * Use [encryptingSink] to wrap a sink instead.
     */
    public fun encryptingSource(plaintext: RawSource, associatedData: ByteArray?): RawSource

    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * with optional [associatedData].
     *
     * Use [encryptingSink] to wrap a sink instead.
     */
    public fun encryptingSource(plaintext: RawSource, associatedData: ByteString?): RawSource {
        return encryptingSource(plaintext, associatedData?.asByteArray())
    }


    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], without associated data.
     *
     * Use [encryptingSource] to wrap a source instead.
     */
    public override fun encryptingSink(ciphertext: RawSink): RawSink {
        return encryptingSink(ciphertext, null as ByteArray?)
    }

    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], with optional [associatedData].
     *
     * Use [encryptingSource] to wrap a source instead.
     */
    public fun encryptingSink(ciphertext: RawSink, associatedData: ByteArray?): RawSink

    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], with optional [associatedData].
     *
     * Use [encryptingSource] to wrap a source instead.
     */
    public fun encryptingSink(ciphertext: RawSink, associatedData: ByteString?): RawSink {
        return encryptingSink(ciphertext, associatedData?.asByteArray())
    }
}

/**
 * Decrypts ciphertext with optional associated data for authenticated encryption (AEAD).
 * When associated data is provided, it is verified during decryption.
 * When associated data is `null`, only the ciphertext authenticity is verified.
 *
 * For the encryption counterpart, see [AuthenticatedEncryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {

    /**
     * Decrypts the given [ciphertext] without associated data
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decryptBlocking] when calling from non-suspending code.
     */
    public override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
        return decrypt(ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] without associated data
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decryptBlocking] when calling from non-suspending code.
     */
    public override suspend fun decrypt(ciphertext: ByteString): ByteString {
        return decrypt(ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decryptBlocking] when calling from non-suspending code.
     */
    public suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return decryptBlocking(ciphertext, associatedData)
    }

    /**
     * Decrypts the given [ciphertext] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decryptBlocking] when calling from non-suspending code.
     */
    public suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString?): ByteString {
        return decrypt(ciphertext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    /**
     * Decrypts the given [ciphertext] without associated data
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decrypt] when calling from suspending code.
     */
    public override fun decryptBlocking(ciphertext: ByteArray): ByteArray {
        return decryptBlocking(ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] without associated data
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decrypt] when calling from suspending code.
     */
    public override fun decryptBlocking(ciphertext: ByteString): ByteString {
        return decryptBlocking(ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decrypt] when calling from suspending code.
     */
    public fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    /**
     * Decrypts the given [ciphertext] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decrypt] when calling from suspending code.
     */
    public fun decryptBlocking(ciphertext: ByteString, associatedData: ByteString?): ByteString {
        return decryptBlocking(ciphertext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * without associated data.
     *
     * Use [decryptingSink] to wrap a sink instead.
     */
    public override fun decryptingSource(ciphertext: RawSource): RawSource {
        return decryptingSource(ciphertext, null as ByteArray?)
    }

    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * with optional [associatedData].
     *
     * Use [decryptingSink] to wrap a sink instead.
     */
    public fun decryptingSource(ciphertext: RawSource, associatedData: ByteArray?): RawSource

    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * with optional [associatedData].
     *
     * Use [decryptingSink] to wrap a sink instead.
     */
    public fun decryptingSource(ciphertext: RawSource, associatedData: ByteString?): RawSource {
        return decryptingSource(ciphertext, associatedData?.asByteArray())
    }


    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], without associated data.
     *
     * Use [decryptingSource] to wrap a source instead.
     */
    public override fun decryptingSink(plaintext: RawSink): RawSink {
        return decryptingSink(plaintext, null as ByteArray?)
    }

    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], with optional [associatedData].
     *
     * Use [decryptingSource] to wrap a source instead.
     */
    public fun decryptingSink(plaintext: RawSink, associatedData: ByteArray?): RawSink

    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], with optional [associatedData].
     *
     * Use [decryptingSource] to wrap a source instead.
     */
    public fun decryptingSink(plaintext: RawSink, associatedData: ByteString?): RawSink {
        return decryptingSink(plaintext, associatedData?.asByteArray())
    }
}
