/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

/**
 * Extends [Cipher] with the ability to set explicit initialization vector (IV) support.
 *
 * Inherited encrypt/decrypt methods generate a random IV and prepend it to the output:
 * [encrypt] returns `IV || ciphertext`, and [decrypt] expects the same format.
 *
 * The `WithIv` variants use a caller-provided IV and do not include it in the output:
 * [encrypt] returns only `ciphertext`, and [decrypt] expects only `ciphertext`.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvCipher : Cipher, IvEncryptor, IvDecryptor

/**
 * Encrypts plaintext with an explicit initialization vector (IV).
 * The `WithIv` methods return only the ciphertext without the IV.
 * All `WithIv` methods are marked [DelicateCryptographyApi] because using a custom IV
 * requires careful handling to avoid security issues such as IV reuse.
 *
 * For the decryption counterpart, see [IvDecryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvEncryptor : Encryptor {
    /**
     * Encrypts the given [plaintext] using the specified [iv]
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return encryptWithIvBlocking(iv, plaintext)
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv]
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString): ByteString {
        return encryptWithIv(iv.asByteArray(), plaintext.asByteArray()).asByteString()
    }

    /**
     * Encrypts the given [plaintext] using the specified [iv]
     * and returns the resulting ciphertext as a [ByteArray].
     *
     * Use [encryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray

    /**
     * Encrypts the given [plaintext] using the specified [iv]
     * and returns the resulting ciphertext as a [ByteString].
     *
     * Use [encryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString): ByteString {
        return encryptWithIvBlocking(iv.asByteArray(), plaintext.asByteArray()).asByteString()
    }


    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * using the specified [iv].
     *
     * Use [encryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource

    /**
     * Returns a [RawSource] that encrypts data as it is read from the given [plaintext] source
     * using the specified [iv].
     *
     * Use [encryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSourceWithIv(iv: ByteString, plaintext: RawSource): RawSource {
        return encryptingSourceWithIv(iv.asByteArray(), plaintext)
    }


    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], using the specified [iv].
     *
     * Use [encryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink

    /**
     * Returns a [RawSink] that encrypts data as it is written, sending the resulting ciphertext
     * to [ciphertext], using the specified [iv].
     *
     * Use [encryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun encryptingSinkWithIv(iv: ByteString, ciphertext: RawSink): RawSink {
        return encryptingSinkWithIv(iv.asByteArray(), ciphertext)
    }
}

/**
 * Decrypts ciphertext with an explicit initialization vector (IV).
 * The `WithIv` methods expect only the ciphertext without a prepended IV.
 * All `WithIv` methods are marked [DelicateCryptographyApi] because they require
 * manual IV management rather than relying on the library to generate IVs safely.
 *
 * For the encryption counterpart, see [IvEncryptor].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface IvDecryptor : Decryptor {
    /**
     * Decrypts the given [ciphertext] using the specified [iv]
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Use [decryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        return decryptWithIvBlocking(iv, ciphertext)
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv]
     * and returns the resulting plaintext as a [ByteString].
     *
     * Use [decryptWithIvBlocking] when calling from non-suspending code.
     */
    @DelicateCryptographyApi
    public suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString): ByteString {
        return decryptWithIv(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
    }

    /**
     * Decrypts the given [ciphertext] using the specified [iv]
     * and returns the resulting plaintext as a [ByteArray].
     *
     * Use [decryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray

    /**
     * Decrypts the given [ciphertext] using the specified [iv]
     * and returns the resulting plaintext as a [ByteString].
     *
     * Use [decryptWithIv] when calling from suspending code.
     */
    @DelicateCryptographyApi
    public fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString): ByteString {
        return decryptWithIvBlocking(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
    }


    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * using the specified [iv].
     *
     * Use [decryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource

    /**
     * Returns a [RawSource] that decrypts data as it is read from the given [ciphertext] source
     * using the specified [iv].
     *
     * Use [decryptingSinkWithIv] to wrap a sink instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSourceWithIv(iv: ByteString, ciphertext: RawSource): RawSource {
        return decryptingSourceWithIv(iv.asByteArray(), ciphertext)
    }


    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], using the specified [iv].
     *
     * Use [decryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink

    /**
     * Returns a [RawSink] that decrypts data as it is written, sending the resulting plaintext
     * to [plaintext], using the specified [iv].
     *
     * Use [decryptingSourceWithIv] to wrap a source instead.
     */
    @DelicateCryptographyApi
    public fun decryptingSinkWithIv(iv: ByteString, plaintext: RawSink): RawSink {
        return decryptingSinkWithIv(iv.asByteArray(), plaintext)
    }
}
