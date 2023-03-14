/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*

import dev.whyoleg.cryptography.materials.key.*
import kotlin.test.*

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeTo(
    formats: Array<KF>,
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
    validate: (key: K, format: KF, bytes: ByteArray) -> Unit,
): List<K> {
    val supportedFormats = formats
        .mapKeys { (formatName, _) -> formatOf(formatName) }
        .filterKeys(supports)

    assertTrue(supportedFormats.isNotEmpty(), "No supported formats")

    val keys = supportedFormats.mapValues { decodeFrom(it.key, it.value) }.values.toList()

    keys.forEach { key ->
        supportedFormats.forEach { (format, bytes) ->
            validate(key, format, bytes)
        }
    }

    return keys
}

fun digest(name: String): CryptographyAlgorithmId<Digest> = when (name) {
    SHA1.name   -> SHA1
    SHA256.name -> SHA256
    SHA384.name -> SHA384
    SHA512.name -> SHA512
    else        -> error("Unknown digest: $name")
}
