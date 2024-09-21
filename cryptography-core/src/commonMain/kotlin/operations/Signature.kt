/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public fun createSignFunction(): SignFunction

    public suspend fun generateSignature(data: ByteArray): ByteArray {
        return generateSignatureBlocking(data)
    }

    public suspend fun generateSignature(data: ByteString): ByteString {
        return generateSignature(data.asByteArray()).asByteString()
    }

    public suspend fun generateSignature(data: RawSource): ByteString {
        return generateSignatureBlocking(data)
    }

    public fun generateSignatureBlocking(data: ByteArray): ByteArray {
        return createSignFunction().use {
            it.update(data)
            it.signToByteArray()
        }
    }

    public fun generateSignatureBlocking(data: ByteString): ByteString {
        return generateSignatureBlocking(data.asByteArray()).asByteString()
    }

    public fun generateSignatureBlocking(data: RawSource): ByteString {
        return createSignFunction().use {
            it.update(data)
            it.sign()
        }
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignFunction : UpdateFunction {
    public fun signIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int
    public fun signToByteArray(): ByteArray
    public fun sign(): ByteString {
        return signToByteArray().asByteString()
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public fun createVerifyFunction(): VerifyFunction

    public suspend fun tryVerifySignature(data: ByteArray, signature: ByteArray): Boolean {
        return tryVerifySignatureBlocking(data, signature)
    }

    public suspend fun tryVerifySignature(data: ByteString, signature: ByteString): Boolean {
        return tryVerifySignature(data.asByteArray(), signature.asByteArray())
    }

    public suspend fun tryVerifySignature(data: RawSource, signature: ByteString): Boolean {
        return tryVerifySignatureBlocking(data, signature)
    }

    public fun tryVerifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean {
        return createVerifyFunction().use {
            it.update(data)
            it.tryVerify(signature)
        }
    }

    public fun tryVerifySignatureBlocking(data: ByteString, signature: ByteString): Boolean {
        return tryVerifySignatureBlocking(data.asByteArray(), signature.asByteArray())
    }

    public fun tryVerifySignatureBlocking(data: RawSource, signature: ByteString): Boolean {
        return createVerifyFunction().use {
            it.update(data)
            it.tryVerify(signature)
        }
    }

    public suspend fun verifySignature(data: ByteArray, signature: ByteArray) {
        return verifySignatureBlocking(data, signature)
    }

    public suspend fun verifySignature(data: ByteString, signature: ByteString) {
        return verifySignature(data.asByteArray(), signature.asByteArray())
    }

    public suspend fun verifySignature(data: RawSource, signature: ByteString) {
        return verifySignatureBlocking(data, signature)
    }

    public fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Unit {
        createVerifyFunction().use {
            it.update(data)
            it.verify(signature)
        }
    }

    public fun verifySignatureBlocking(data: ByteString, signature: ByteString) {
        return verifySignatureBlocking(data.asByteArray(), signature.asByteArray())
    }

    public fun verifySignatureBlocking(data: RawSource, signature: ByteString): Unit {
        createVerifyFunction().use {
            it.update(data)
            it.verify(signature)
        }
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface VerifyFunction : UpdateFunction {
    public fun tryVerify(signature: ByteArray, startIndex: Int = 0, endIndex: Int = signature.size): Boolean
    public fun tryVerify(signature: ByteString, startIndex: Int = 0, endIndex: Int = signature.size): Boolean {
        return tryVerify(signature.asByteArray(), startIndex, endIndex)
    }

    public fun verify(signature: ByteArray, startIndex: Int = 0, endIndex: Int = signature.size)
    public fun verify(signature: ByteString, startIndex: Int = 0, endIndex: Int = signature.size) {
        return verify(signature.asByteArray(), startIndex, endIndex)
    }
}
