/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.functions.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public fun createSignFunction(): SignFunction

    public suspend fun generateSignature(data: ByteArray): ByteArray = generateSignatureBlocking(data)
    public suspend fun generateSignature(data: ByteString): ByteString = generateSignature(data.asByteArray()).asByteString()
    public suspend fun generateSignature(data: RawSource): ByteString = generateSignatureBlocking(data)

    public fun generateSignatureBlocking(data: ByteArray): ByteArray = createSignFunction().use {
        it.update(data)
        it.signToByteArray()
    }

    public fun generateSignatureBlocking(data: ByteString): ByteString = generateSignatureBlocking(data.asByteArray()).asByteString()
    public fun generateSignatureBlocking(data: RawSource): ByteString = createSignFunction().use {
        it.update(data)
        it.sign()
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public fun createVerifyFunction(): VerifyFunction

    public suspend fun verifySignature(data: ByteArray, signature: ByteArray): Boolean = verifySignatureBlocking(data, signature)
    public suspend fun verifySignature(data: ByteString, signature: ByteString): Boolean =
        verifySignature(data.asByteArray(), signature.asByteArray())

    public suspend fun verifySignature(data: RawSource, signature: ByteString): Boolean = verifySignatureBlocking(data, signature)

    public fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean = createVerifyFunction().use {
        it.update(data)
        it.verify(signature)
    }

    public fun verifySignatureBlocking(data: ByteString, signature: ByteString): Boolean =
        verifySignatureBlocking(data.asByteArray(), signature.asByteArray())

    public fun verifySignatureBlocking(data: RawSource, signature: ByteString): Boolean = createVerifyFunction().use {
        it.update(data)
        it.verify(signature)
    }
}
