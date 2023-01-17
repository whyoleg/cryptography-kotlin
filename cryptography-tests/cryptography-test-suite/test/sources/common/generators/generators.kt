package dev.whyoleg.cryptography.test.suite.generators

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*

inline fun symmetricKeySizes(block: (keySize: SymmetricKeySize, keyParams: String) -> Unit) {
    listOf(SymmetricKeySize.B128, SymmetricKeySize.B192, SymmetricKeySize.B256).forEach { keySize ->
        block(keySize, "${keySize.value.bits}bits")
    }
}

@OptIn(InsecureAlgorithm::class)
inline fun digests(block: (digest: CryptographyAlgorithmId<Digest>, digestSize: Int) -> Unit) {
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
