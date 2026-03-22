/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

/**
 * Combines the ability to set explicit initialization vector (IV) and authenticated encryption (AEAD) capabilities.
 *
 * Inherited encrypt/decrypt methods generate a random IV and prepend it to the output.
 * The authentication tag is appended to the ciphertext:
 * [encrypt] returns `IV || ciphertext || tag`, and [decrypt] expects the same format.
 *
 * The `WithIv` variants use a caller-provided IV and do not include it in the output:
 * [encrypt] returns `ciphertext || tag`, and [decrypt] expects `ciphertext || tag`.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvAuthenticatedCipher : IvCipher, AuthenticatedCipher, IvAuthenticatedEncryptor, IvAuthenticatedDecryptor

/**
 * Encrypts plaintext with an explicit initialization vector (IV) and optional associated data.
 * The `WithIv` methods return `ciphertext || tag` without the IV.
 * All `WithIv` methods are marked [DelicateCryptographyApi] because using a custom IV
 * requires careful handling to avoid security issues such as IV reuse.
 * When associated data is provided, it is authenticated but not encrypted.
 * When associated data is `null`, only the plaintext is authenticated and encrypted.
 *
 * For the decryption counterpart, see [IvAuthenticatedDecryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvAuthenticatedEncryptor : IvEncryptor, AuthenticatedEncryptor {
    /**
     * Encrypts the given [plaintext] using the specified [iv] without associated data
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    override suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return encryptWithIv(iv, plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv] without associated data
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    override suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString): ByteString {
        return encryptWithIv(iv, plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return encryptWithIvBlocking(iv, plaintext, associatedData)
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString, associatedData: ByteString?): ByteString {
        return encryptWithIv(iv.asByteArray(), plaintext.asByteArray(), associatedData?.toByteArray()).asByteString()
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv] without associated data
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return encryptWithIvBlocking(iv, plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv] without associated data
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    override fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString): ByteString {
        return encryptWithIvBlocking(iv, plaintext, null)
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    /**
     * Encrypts the given [plaintext] using the specified [iv] with optional [associatedData]
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString, associatedData: ByteString?): ByteString {
        return encryptWithIvBlocking(iv.asByteArray(), plaintext.asByteArray(), associatedData?.toByteArray()).asByteString()
    }


    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * using the specified [iv] without associated data.
     *
     * Use [encryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    override fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource {
        return encryptingSourceWithIv(iv, plaintext, null)
    }

    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * using the specified [iv] with optional [associatedData].
     * 
     * Use [encryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource

    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * using the specified [iv] with optional [associatedData].
     * 
     * Use [encryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSourceWithIv(iv: ByteString, plaintext: RawSource, associatedData: ByteString?): RawSource {
        return encryptingSourceWithIv(iv.asByteArray(), plaintext, associatedData?.asByteArray())
    }


    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], using the specified [iv] without associated data.
     *
     * Use [encryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    override fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink {
        return encryptingSinkWithIv(iv, ciphertext, null)
    }

    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], using the specified [iv] with optional [associatedData].
     * 
     * Use [encryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink

    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], using the specified [iv] with optional [associatedData].
     * 
     * Use [encryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSinkWithIv(iv: ByteString, ciphertext: RawSink, associatedData: ByteString?): RawSink {
        return encryptingSinkWithIv(iv.asByteArray(), ciphertext, associatedData?.toByteArray())
    }
}

/**
 * Decrypts ciphertext with an explicit initialization vector (IV) and optional associated data.
 * All `WithIv` methods are marked [DelicateCryptographyApi] because they require
 * manual IV management rather than relying on the library to generate IVs safely.
 * When associated data is provided, it is verified during decryption.
 * When associated data is `null`, only the ciphertext authenticity is verified.
 *
 * For the encryption counterpart, see [IvAuthenticatedEncryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvAuthenticatedDecryptor : IvDecryptor, AuthenticatedDecryptor {

    /**
     * Decrypts the given [ciphertext] using the specified [iv] without associated data
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    override suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        return decryptWithIv(iv, ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv] without associated data
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    override suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString): ByteString {
        return decryptWithIv(iv, ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return decryptWithIvBlocking(iv, ciphertext, associatedData)
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString, associatedData: ByteString?): ByteString {
        return decryptWithIv(iv.asByteArray(), ciphertext.asByteArray(), associatedData?.toByteArray()).asByteString()
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv] without associated data
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        return decryptWithIvBlocking(iv, ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv] without associated data
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext has been tampered with.
     *
     * Use [decryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    override fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString): ByteString {
        return decryptWithIvBlocking(iv, ciphertext, null)
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    /**
     * Decrypts the given [ciphertext] using the specified [iv] with optional [associatedData]
     * and returns the resulting plaintext as a [ByteString].
     *
     * Throws an exception if the authentication tag verification fails, indicating the ciphertext or associated data has been tampered with.
     *
     * Use [decryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString, associatedData: ByteString?): ByteString {
        return decryptWithIvBlocking(iv.asByteArray(), ciphertext.asByteArray(), associatedData?.toByteArray()).asByteString()
    }


    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * using the specified [iv] without associated data.
     *
     * Use [decryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    override fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource {
        return decryptingSourceWithIv(iv, ciphertext, null)
    }

    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * using the specified [iv] with optional [associatedData].
     *
     * Use [decryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource, associatedData: ByteArray?): RawSource

    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * using the specified [iv] with optional [associatedData].
     *
     * Use [decryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSourceWithIv(iv: ByteString, ciphertext: RawSource, associatedData: ByteString?): RawSource {
        return decryptingSourceWithIv(iv.asByteArray(), ciphertext, associatedData?.asByteArray())
    }


    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], using the specified [iv] without associated data.
     *
     * Use [decryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    override fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink {
        return decryptingSinkWithIv(iv, plaintext, null)
    }

    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], using the specified [iv] with optional [associatedData].
     *
     * Use [decryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink, associatedData: ByteArray?): RawSink

    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], using the specified [iv] with optional [associatedData].
     *
     * Use [decryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSinkWithIv(iv: ByteString, plaintext: RawSink, associatedData: ByteString?): RawSink {
        return decryptingSinkWithIv(iv.asByteArray(), plaintext, associatedData?.toByteArray())
    }
}
