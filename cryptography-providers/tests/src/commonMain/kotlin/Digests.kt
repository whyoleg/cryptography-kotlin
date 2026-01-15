/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*

val Digests = listOf(
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
)

val DigestsForCompatibility = listOf(
    SHA1,
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
)

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

fun CryptographyAlgorithmId<Digest>.digestSize(): Int = when (this) {
    MD5      -> 16
    SHA1     -> 20
    SHA224   -> 28
    SHA256   -> 32
    SHA384   -> 48
    SHA512   -> 64
    SHA3_224 -> 28
    SHA3_256 -> 32
    SHA3_384 -> 48
    SHA3_512 -> 64
    else     -> error("Unknown digest: $this")
}
