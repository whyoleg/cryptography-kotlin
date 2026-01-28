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
) {
    val expected = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), expectedBytes.toByteArray())
    val actual = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), actualBytes.toByteArray())

    // we can't really assert the version here, as it might be different depending on the availability of the public key
    // assertEquals(expected.version, actual.version, "PrivateKeyInfo.version")
    assertEquals(expected.privateKeyAlgorithm, actual.privateKeyAlgorithm, "PrivateKeyInfo.privateKeyAlgorithm")
    assertContentEquals(expected.privateKey, actual.privateKey, "PrivateKeyInfo.privateKey")

    // public key is an optional field, so it might be not available in some providers
    if (expected.publicKey != null && actual.publicKey != null) {
        assertEquals(expected.publicKey?.unusedBits, actual.publicKey?.unusedBits, "PrivateKeyInfo.publicKey.unusedBits")
        assertContentEquals(expected.publicKey?.byteArray, actual.publicKey?.byteArray, "PrivateKeyInfo.publicKey.byteArray")
    }
}
