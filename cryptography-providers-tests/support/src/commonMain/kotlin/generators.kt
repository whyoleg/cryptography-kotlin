/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*

inline fun generateSymmetricKeySize(block: (keySize: SymmetricKeySize) -> Unit) {
    generate(block, SymmetricKeySize.B128, SymmetricKeySize.B192, SymmetricKeySize.B256)
}

inline fun generateRsaKeySizes(block: (keySize: BinarySize) -> Unit) {
    generate(block, 2048.bits, 3072.bits, 4096.bits)
}

@OptIn(InsecureAlgorithm::class)
inline fun generateDigests(block: (digest: CryptographyAlgorithmId<Digest>, digestSize: Int) -> Unit) {
    listOf(
        SHA1 to 20,
        SHA256 to 32,
        SHA384 to 48,
        SHA512 to 64,
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
