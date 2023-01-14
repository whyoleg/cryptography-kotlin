package dev.whyoleg.cryptography.test.suite.generators

import dev.whyoleg.cryptography.algorithms.symmetric.*

inline fun symmetricKeySizes(block: (keySize: SymmetricKeySize, keyParams: String) -> Unit) {
    listOf(SymmetricKeySize.B128, SymmetricKeySize.B192, SymmetricKeySize.B256).forEach { keySize ->
        block(keySize, "${keySize.value.bits}bits")
    }
}
