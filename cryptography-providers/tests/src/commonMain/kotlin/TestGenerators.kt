/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*

inline fun generateSymmetricKeySize(block: (keySize: BinarySize) -> Unit) {
    generate(block, AES.Key.Size.B128, AES.Key.Size.B192, AES.Key.Size.B256)
}

inline fun generateRsaKeySizes(block: (keySize: BinarySize) -> Unit) {
    generate(block, 2048.bits, 3072.bits, 4096.bits)
}

val CommonDigests = listOf(
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

inline fun generateDigests(block: (digest: CryptographyAlgorithmId<Digest>, digestSize: Int) -> Unit) {
    listOf(
        SHA1 to 20,
        SHA224 to 28,
        SHA256 to 32,
        SHA384 to 48,
        SHA512 to 64,
        SHA3_224 to 28,
        SHA3_256 to 32,
        SHA3_384 to 48,
        SHA3_512 to 64,
    ).forEach { block(it.first, it.second) }
}

val DigestsForCompatibility = listOf(
    SHA1,
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
)

inline fun generateDigestsForCompatibility(block: (digest: CryptographyAlgorithmId<Digest>, digestSize: Int) -> Unit) {
    listOf(
        SHA1 to 20,
        SHA256 to 32,
        SHA512 to 64,
        SHA3_256 to 32,
        SHA3_512 to 64,
    ).forEach { block(it.first, it.second) }
}

suspend inline fun <K : Key> KeyGenerator<K>.generateKeys(count: Int, block: (key: K) -> Unit) {
    repeat(count) { block(generateKey()) }
}

inline fun <T> generate(block: (value: T) -> Unit, vararg values: T) {
    values.forEach { block(it) }
}

inline fun generateBoolean(block: (value: Boolean) -> Unit) {
    generate(block, true, false)
}
