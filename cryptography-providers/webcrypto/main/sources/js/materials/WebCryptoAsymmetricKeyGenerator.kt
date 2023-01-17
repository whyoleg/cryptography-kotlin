package dev.whyoleg.cryptography.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoAsymmetricKeyGenerator<K : Key>(
    private val algorithm: AsymmetricKeyGenerationAlgorithm,
    private val keyUsages: Array<String>,
    private val keyPairWrapper: (CryptoKeyPair) -> K,
) : KeyGenerator<K> {
    override suspend fun generateKey(): K {
        return keyPairWrapper(WebCrypto.subtle.generateKey(algorithm, true, keyUsages).await())
    }

    override fun generateKeyBlocking(): K = nonBlocking()
}
