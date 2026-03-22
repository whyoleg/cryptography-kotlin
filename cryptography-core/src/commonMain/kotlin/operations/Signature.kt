/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

/**
 * Generates signatures over data.
 *
 * For the verification counterpart, see [SignatureVerifier].
 *
 * Use [generateSignature] for one-shot generation, or [createSignFunction] for incremental (streaming) signing.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    /**
     * Returns a new [SignFunction] for incremental signing.
     *
     * The returned function accumulates data fed via [UpdateFunction.update] and produces
     * a signature when finalized. The function should be [closed][AutoCloseable.close] after use.
     */
    public fun createSignFunction(): SignFunction

    /**
     * Signs the given [data] and returns the resulting signature as a [ByteArray].
     *
     * Use [generateSignatureBlocking] when calling from non-suspending code.
     */
    public suspend fun generateSignature(data: ByteArray): ByteArray {
        return generateSignatureBlocking(data)
    }

    /**
     * Signs the given [data] and returns the resulting signature as a [ByteString].
     *
     * Use [generateSignatureBlocking] when calling from non-suspending code.
     */
    public suspend fun generateSignature(data: ByteString): ByteString {
        return generateSignature(data.asByteArray()).asByteString()
    }

    /**
     * Signs the given [data] read from a [RawSource] and returns the resulting signature as a [ByteString].
     *
     * Use [generateSignatureBlocking] when calling from non-suspending code.
     */
    public suspend fun generateSignature(data: RawSource): ByteString {
        return generateSignatureBlocking(data)
    }

    /**
     * Signs the given [data] and returns the resulting signature as a [ByteArray].
     *
     * Use [generateSignature] when calling from suspending code.
     */
    public fun generateSignatureBlocking(data: ByteArray): ByteArray {
        return createSignFunction().use {
            it.update(data)
            it.signToByteArray()
        }
    }

    /**
     * Signs the given [data] and returns the resulting signature as a [ByteString].
     *
     * Use [generateSignature] when calling from suspending code.
     */
    public fun generateSignatureBlocking(data: ByteString): ByteString {
        return generateSignatureBlocking(data.asByteArray()).asByteString()
    }

    /**
     * Signs the given [data] read from a [RawSource] and returns the resulting signature as a [ByteString].
     *
     * Use [generateSignature] when calling from suspending code.
     */
    public fun generateSignatureBlocking(data: RawSource): ByteString {
        return createSignFunction().use {
            it.update(data)
            it.sign()
        }
    }
}

/**
 * An incremental signing function that accumulates data and produces a signature on finalization.
 *
 * Data is fed via [update] and the signature is obtained by calling one of the finalization methods:
 * [signIntoByteArray], [signToByteArray], or [sign].
 * After finalization, the function can be [reset] and reused, or [closed][close] to release resources.
 *
 * Obtained via [SignatureGenerator.createSignFunction].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignFunction : UpdateFunction {
    /**
     * Finalizes the signature computation and writes the result into [destination]
     * starting at [destinationOffset], and returns the number of bytes written.
     */
    public fun signIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int

    /**
     * Finalizes the signature computation and returns the result as a new [ByteArray].
     */
    public fun signToByteArray(): ByteArray

    /**
     * Finalizes the signature computation and returns the result as a [ByteString].
     */
    public fun sign(): ByteString {
        return signToByteArray().asByteString()
    }
}

/**
 * Verifies signatures against data.
 *
 * There are two families of verification methods:
 * - [tryVerifySignature] / [VerifyFunction.tryVerify] — returns `false` if the signature does not match.
 * - [verifySignature] / [VerifyFunction.verify] — throws an exception if the signature does not match.
 *
 * Use [verifySignature]/[tryVerifySignature] for one-shot verification, or [createVerifyFunction] for incremental (streaming) verification.
 *
 * For the signing counterpart, see [SignatureGenerator].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    /**
     * Returns a new [VerifyFunction] for incremental verification.
     *
     * The returned function accumulates data fed via [UpdateFunction.update] and checks the signature
     * when finalized. The function should be [closed][AutoCloseable.close] after use.
     */
    public fun createVerifyFunction(): VerifyFunction

    /**
     * Verifies that [signature] is valid for the given [data].
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * Use [tryVerifySignatureBlocking] when calling from non-suspending code.
     * For a throwing variant, use [verifySignature].
     */
    public suspend fun tryVerifySignature(data: ByteArray, signature: ByteArray): Boolean {
        return tryVerifySignatureBlocking(data, signature)
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * Use [tryVerifySignatureBlocking] when calling from non-suspending code.
     * For a throwing variant, use [verifySignature].
     */
    public suspend fun tryVerifySignature(data: ByteString, signature: ByteString): Boolean {
        return tryVerifySignature(data.asByteArray(), signature.asByteArray())
    }

    /**
     * Verifies that [signature] is valid for the given [data] read from a [RawSource].
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * Use [tryVerifySignatureBlocking] when calling from non-suspending code.
     * For a throwing variant, use [verifySignature].
     */
    public suspend fun tryVerifySignature(data: RawSource, signature: ByteString): Boolean {
        return tryVerifySignatureBlocking(data, signature)
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * Use [tryVerifySignature] when calling from suspending code.
     * For a throwing variant, use [verifySignatureBlocking].
     */
    public fun tryVerifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean {
        return createVerifyFunction().use {
            it.update(data)
            it.tryVerify(signature)
        }
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * Use [tryVerifySignature] when calling from suspending code.
     * For a throwing variant, use [verifySignatureBlocking].
     */
    public fun tryVerifySignatureBlocking(data: ByteString, signature: ByteString): Boolean {
        return tryVerifySignatureBlocking(data.asByteArray(), signature.asByteArray())
    }

    /**
     * Verifies that [signature] is valid for the given [data] read from a [RawSource].
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * Use [tryVerifySignature] when calling from suspending code.
     * For a throwing variant, use [verifySignatureBlocking].
     */
    public fun tryVerifySignatureBlocking(data: RawSource, signature: ByteString): Boolean {
        return createVerifyFunction().use {
            it.update(data)
            it.tryVerify(signature)
        }
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Throws an exception if the signature is not valid.
     *
     * Use [verifySignatureBlocking] when calling from non-suspending code.
     * For a non-throwing variant that returns a Boolean, use [tryVerifySignature].
     */
    public suspend fun verifySignature(data: ByteArray, signature: ByteArray) {
        return verifySignatureBlocking(data, signature)
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Throws an exception if the signature is not valid.
     *
     * Use [verifySignatureBlocking] when calling from non-suspending code.
     * For a non-throwing variant that returns a Boolean, use [tryVerifySignature].
     */
    public suspend fun verifySignature(data: ByteString, signature: ByteString) {
        return verifySignature(data.asByteArray(), signature.asByteArray())
    }

    /**
     * Verifies that [signature] is valid for the given [data] read from a [RawSource].
     * Throws an exception if the signature is not valid.
     *
     * Use [verifySignatureBlocking] when calling from non-suspending code.
     * For a non-throwing variant that returns a Boolean, use [tryVerifySignature].
     */
    public suspend fun verifySignature(data: RawSource, signature: ByteString) {
        return verifySignatureBlocking(data, signature)
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Throws an exception if the signature is not valid.
     *
     * Use [verifySignature] when calling from suspending code.
     * For a non-throwing variant that returns a Boolean, use [tryVerifySignatureBlocking].
     */
    public fun verifySignatureBlocking(data: ByteArray, signature: ByteArray) {
        createVerifyFunction().use {
            it.update(data)
            it.verify(signature)
        }
    }

    /**
     * Verifies that [signature] is valid for the given [data].
     * Throws an exception if the signature is not valid.
     *
     * Use [verifySignature] when calling from suspending code.
     * For a non-throwing variant that returns a Boolean, use [tryVerifySignatureBlocking].
     */
    public fun verifySignatureBlocking(data: ByteString, signature: ByteString) {
        return verifySignatureBlocking(data.asByteArray(), signature.asByteArray())
    }

    /**
     * Verifies that [signature] is valid for the given [data] read from a [RawSource].
     * Throws an exception if the signature is not valid.
     *
     * Use [verifySignature] when calling from suspending code.
     * For a non-throwing variant that returns a Boolean, use [tryVerifySignatureBlocking].
     */
    public fun verifySignatureBlocking(data: RawSource, signature: ByteString) {
        createVerifyFunction().use {
            it.update(data)
            it.verify(signature)
        }
    }
}

/**
 * An incremental verification function that accumulates data and checks a signature on finalization.
 *
 * Data is fed via [update] and verification is performed by calling one of the finalization methods:
 * * [tryVerify] — returns `false` if the signature does not match.
 * * [verify] — throws an exception if the signature does not match.
 *
 * After finalization, the function can be [reset] and reused, or [closed][close] to release resources.
 *
 * Obtained via [SignatureVerifier.createVerifyFunction].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface VerifyFunction : UpdateFunction {
    /**
     * Checks whether the [signature] (or its subrange from [startIndex] to [endIndex])
     * is valid for the data fed so far.
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * For a throwing variant, use [verify].
     */
    public fun tryVerify(signature: ByteArray, startIndex: Int = 0, endIndex: Int = signature.size): Boolean

    /**
     * Checks whether the [signature] (or its subrange from [startIndex] to [endIndex])
     * is valid for the data fed so far.
     * Returns `true` if the signature is valid, `false` otherwise.
     *
     * For a throwing variant, use [verify].
     */
    public fun tryVerify(signature: ByteString, startIndex: Int = 0, endIndex: Int = signature.size): Boolean {
        return tryVerify(signature.asByteArray(), startIndex, endIndex)
    }

    /**
     * Checks whether the [signature] (or its subrange from [startIndex] to [endIndex])
     * is valid for the data fed so far.
     * Throws an exception if the signature is not valid.
     *
     * For a non-throwing variant that returns a Boolean, use [tryVerify].
     */
    public fun verify(signature: ByteArray, startIndex: Int = 0, endIndex: Int = signature.size)

    /**
     * Checks whether the [signature] (or its subrange from [startIndex] to [endIndex])
     * is valid for the data fed so far.
     * Throws an exception if the signature is not valid.
     *
     * For a non-throwing variant that returns a Boolean, use [tryVerify].
     */
    public fun verify(signature: ByteString, startIndex: Int = 0, endIndex: Int = signature.size) {
        return verify(signature.asByteArray(), startIndex, endIndex)
    }
}
