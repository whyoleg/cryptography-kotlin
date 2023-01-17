package dev.whyoleg.cryptography.test.vectors.suite

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.provider.*

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeTo(format: KF?): Buffer? {
    return format?.let { encodeTo(it) }
}

suspend fun <KF : KeyFormat, K : Key> KeyDecoder<KF, K>.decodeFrom(format: KF?, input: Buffer): K? {
    return format?.let { decodeFrom(it, input) }
}

fun ByteArray.assertContentEquals(expected: Buffer) {
    kotlin.test.assertContentEquals(expected, this)
}

fun Boolean.assertTrue() {
    kotlin.test.assertTrue(this)
}

object StringKeyFormat {
    val RAW = "RAW"
    val JWK = "JWK"
    val DER = "DER"
    val PEM = "PEM"
}

fun CryptographyProvider.skipUnsupported(feature: String, supports: Boolean): Boolean {
    if (supports) return true

    println("[TEST] SKIP: $feature is not supported by $name")
    return false
}
