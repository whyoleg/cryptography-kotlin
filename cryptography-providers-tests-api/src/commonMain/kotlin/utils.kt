/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*

import dev.whyoleg.cryptography.materials.key.*
import kotlin.test.*

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeTo(
    formats: Collection<KF>,
    supports: (KF) -> Boolean,
): Map<String, ByteArray> = formats.filter(supports).associate {
    it.name to encodeTo(it)
}.also {
    assertTrue(it.isNotEmpty(), "No supported formats")
}

suspend inline fun <KF : KeyFormat, K : EncodableKey<KF>> KeyDecoder<KF, K>.decodeFrom(
    formats: Map<String, ByteArray>,
    formatOf: (String) -> KF,
    supports: (KF) -> Boolean,
    supportsDecoding: (KF, ByteArray) -> Boolean = { _, _ -> true },
    validate: (key: K, format: KF, bytes: ByteArray) -> Unit,
): List<K> {
    val supportedFormats = formats
        .mapKeys { (formatName, _) -> formatOf(formatName) }
        .filterKeys(supports)

    val keys = supportedFormats.mapNotNull {
        if (supportsDecoding(it.key, it.value)) decodeFrom(it.key, it.value) else null
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
