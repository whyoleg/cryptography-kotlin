/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*
import kotlin.test.*

// base64 is used to have better messages
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

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeTo(
    formats: Collection<KF>,
    supports: (KF) -> Boolean,
): Map<String, ByteString> = formats.filter(supports).associate {
    it.name to encodeToByteString(it)
}.also {
    assertTrue(it.isNotEmpty(), "No supported formats")
}

inline fun <KF : KeyFormat> Map<String, ByteString>.filterSupportedFormats(
    formatOf: (String) -> KF,
    supports: (KF) -> Boolean,
): Map<KF, ByteString> = mapKeys { (formatName, _) -> formatOf(formatName) }.filterKeys(supports)

suspend inline fun <KF : KeyFormat, K : EncodableKey<KF>> KeyDecoder<KF, K>.decodeFrom(
    formats: Map<String, ByteString>,
    formatOf: (String) -> KF,
    supports: (KF) -> Boolean,
    supportsDecoding: (KF, ByteString) -> Boolean = { _, _ -> true },
    validate: suspend (key: K, format: KF, bytes: ByteString) -> Unit,
): List<K> {
    val supportedFormats = formats.filterSupportedFormats(formatOf, supports)

    val keys = supportedFormats.mapNotNull {
        if (supportsDecoding(it.key, it.value)) decodeFromByteString(it.key, it.value) else null
    }

    keys.forEach { key ->
        supportedFormats.forEach { (format, bytes) ->
            validate(key, format, bytes)
        }
    }

    return keys
}

suspend inline fun <K : Key> KeyGenerator<K>.generateKeys(count: Int, block: (key: K) -> Unit) {
    repeat(count) { block(generateKey()) }
}

fun Buffer(bytes: ByteString): Buffer = Buffer().apply { write(bytes) }

fun Buffer.bufferedSource(): Source = (this as RawSource).buffered()
fun Buffer.bufferedSink(): Sink = (this as RawSink).buffered()
