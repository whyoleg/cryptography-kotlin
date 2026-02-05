/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*
import kotlin.test.*

// base64 is used to have better messages

// TODO: OVERLOAD_RESOLUTION_AMBIGUITY
//fun assertContentEquals(expected: ByteArray?, actual: ByteArray?, message: String? = null) {
//    assertEquals(expected?.let(Base64::encode), actual?.let(Base64::encode), message)
//}

fun assertContentEquals(expected: ByteString?, actual: ByteString?, message: String? = null) {
    assertEquals(expected?.let(Base64::encode), actual?.let(Base64::encode), message)
}

suspend fun SignatureVerifier.assertVerifySignature(
    data: ByteArray,
    signature: ByteArray,
    message: String = "Invalid signature",
) {
    verifySignature(data, signature)
    assertTrue(tryVerifySignature(data, signature), message)
}

suspend fun SignatureVerifier.assertVerifySignature(
    data: ByteString,
    signature: ByteString,
    message: String = "Invalid signature",
) {
    verifySignature(data, signature)
    assertTrue(tryVerifySignature(data, signature), message)
}

fun assertPrivateKeyInfoEquals(
    expectedBytes: ByteString,
    actualBytes: ByteString,
    assertPrivateKeyAlgorithm: (expected: AlgorithmIdentifier, actual: AlgorithmIdentifier) -> Unit = { expected, actual ->
        assertEquals(expected, actual, "PrivateKeyInfo.privateKeyAlgorithm")
    },
) {
    val expected = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), expectedBytes.toByteArray())
    val actual = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), actualBytes.toByteArray())

    // we can't really assert the version here, as it might be different depending on the availability of the public key
    // assertEquals(expected.version, actual.version, "PrivateKeyInfo.version")
    assertPrivateKeyAlgorithm(expected.privateKeyAlgorithm, actual.privateKeyAlgorithm)
    assertContentEquals(expected.privateKey, actual.privateKey, "PrivateKeyInfo.privateKey")

    // public key is an optional field, so it might be not available in some providers
    if (expected.publicKey != null && actual.publicKey != null) {
        assertBitArrayEquals(expected.publicKey, actual.publicKey, "PrivateKeyInfo.publicKey")
    }
}

fun assertBitArrayEquals(
    expected: BitArray?,
    actual: BitArray?,
    message: String = "BitArray",
) {
    assertEquals(expected?.unusedBits, actual?.unusedBits, "$message.unusedBits")
    assertContentEquals(expected?.byteArray, actual?.byteArray, "$message.byteArray")
}
