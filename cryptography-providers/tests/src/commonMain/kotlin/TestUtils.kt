/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.test.*

suspend fun <F : EncodingFormat> Encodable<F>.encodeTo(
    formats: Collection<F>,
    supports: (F) -> Boolean,
): Map<String, ByteString> = formats.filter(supports).associate {
    it.name to encodeToByteString(it)
}.also {
    assertTrue(it.isNotEmpty(), "No supported formats")
}

inline fun <F : EncodingFormat> Map<String, ByteString>.filterSupportedFormats(
    formatOf: (String) -> F,
    supports: (F) -> Boolean,
): Map<F, ByteString> = mapKeys { (formatName, _) -> formatOf(formatName) }.filterKeys(supports)

suspend inline fun <F : EncodingFormat, K : Encodable<F>> Decoder<F, K>.decodeFrom(
    formats: Map<String, ByteString>,
    formatOf: (String) -> F,
    supports: (F) -> Boolean,
    supportsDecoding: (F, ByteString) -> Boolean = { _, _ -> true },
    validate: suspend (key: K, format: F, bytes: ByteString) -> Unit,
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

suspend inline fun <K> KeyGenerator<K>.generateKeys(count: Int, block: (key: K) -> Unit) {
    repeat(count) { block(generateKey()) }
}

fun Buffer(bytes: ByteString): Buffer = Buffer().apply { write(bytes) }

fun Buffer.bufferedSource(): Source = (this as RawSource).buffered()
fun Buffer.bufferedSink(): Sink = (this as RawSink).buffered()
