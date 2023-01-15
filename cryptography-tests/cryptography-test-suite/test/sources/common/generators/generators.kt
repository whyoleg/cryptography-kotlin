package dev.whyoleg.cryptography.test.suite.generators

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*

inline fun symmetricKeySizes(block: (keySize: SymmetricKeySize, keyParams: String) -> Unit) {
    listOf(SymmetricKeySize.B128, SymmetricKeySize.B192, SymmetricKeySize.B256).forEach { keySize ->
        block(keySize, "${keySize.value.bits}bits")
    }
}

@OptIn(InsecureAlgorithm::class)
inline fun digests(block: (digest: CryptographyAlgorithmId<Digest>) -> Unit) {
    listOf(SHA1, SHA256, SHA384, SHA512).forEach(block)
}
