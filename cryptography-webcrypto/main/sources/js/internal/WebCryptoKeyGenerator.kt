package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal abstract class WebCryptoSymmetricKeyGenerator<K>(
    private val algorithm: SymmetricKeyGenerationAlgorithm,
    private val keyUsages: Array<String>,
) : KeyGenerator<K> {
    protected abstract fun wrap(key: CryptoKey): K
    final override suspend fun generateKey(): K {
        return wrap(WebCrypto.subtle.generateKey(algorithm, true, keyUsages).await())
    }

    final override fun generateKeyBlocking(): K = nonBlocking()
}

internal abstract class WebCryptoAsymmetricKeyGenerator<K>(
    private val algorithm: AsymmetricKeyGenerationAlgorithm,
    private val keyUsages: Array<String>,
) : KeyGenerator<K> {
    protected abstract fun wrap(keyPair: CryptoKeyPair): K
    final override suspend fun generateKey(): K {
        return wrap(WebCrypto.subtle.generateKey(algorithm, true, keyUsages).await())
    }

    override fun generateKeyBlocking(): K = nonBlocking()
}
