package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*

suspend fun <KF : KeyFormat, K : Key> KeyDecoder<KF, K>.decodeFrom(
    formats: Map<String, Buffer>,
    mapFormat: (String) -> KF?,
): List<K> = formats.mapNotNull { (stringFormat, data) ->
    mapFormat(stringFormat)?.let { decodeFrom(it, data) }
}

object StringKeyFormat {
    val RAW = "RAW"
    val JWK = "JWK"
    val DER = "DER"
    val PEM = "PEM"
}

fun digest(name: String): CryptographyAlgorithmId<Digest> = when (name) {
    SHA1.name   -> SHA1
    SHA256.name -> SHA256
    SHA384.name -> SHA384
    SHA512.name -> SHA512
    else        -> error("Unknown digest: $name")
}
