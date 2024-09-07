/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*

import dev.whyoleg.cryptography.materials.key.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*
import kotlin.test.*

// base64 is used to have better messages
fun assertContentEquals(expected: ByteString?, actual: ByteString?, message: String? = null) {
    assertEquals(expected?.let(Base64::encode), actual?.let(Base64::encode), message)
}

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeTo(
    formats: Collection<KF>,
    supports: (KF) -> Boolean,
): Map<String, ByteString> = formats.filter(supports).associate {
    it.name to encodeToByteString(it)
}.also {
    assertTrue(it.isNotEmpty(), "No supported formats")
}

suspend inline fun <KF : KeyFormat, K : EncodableKey<KF>> KeyDecoder<KF, K>.decodeFrom(
    formats: Map<String, ByteString>,
    formatOf: (String) -> KF,
    supports: (KF) -> Boolean,
    supportsDecoding: (KF, ByteString) -> Boolean = { _, _ -> true },
    validate: (key: K, format: KF, bytes: ByteString) -> Unit,
): List<K> {
    val supportedFormats = formats
        .mapKeys { (formatName, _) -> formatOf(formatName) }
        .filterKeys(supports)

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

fun digest(name: String): CryptographyAlgorithmId<Digest> = when (name) {
    MD5.name      -> MD5
    SHA1.name     -> SHA1
    SHA224.name   -> SHA224
    SHA256.name   -> SHA256
    SHA384.name   -> SHA384
    SHA512.name   -> SHA512
    SHA3_224.name -> SHA3_224
    SHA3_256.name -> SHA3_256
    SHA3_384.name -> SHA3_384
    SHA3_512.name -> SHA3_512
    else          -> error("Unknown digest: $name")
}

expect fun disableJsConsoleDebug()

// Wasm tests on browser cannot be filtered: https://youtrack.jetbrains.com/issue/KT-58291
@OptIn(ExperimentalMultiplatform::class)
@OptionalExpectation
expect annotation class WasmIgnore()
