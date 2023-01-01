package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.materials.*
import dev.whyoleg.cryptography.jdk.operations.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.materials.key.KeyGenerator
import dev.whyoleg.cryptography.operations.signature.*
import javax.crypto.*

internal class JdkHmac(
    private val state: JdkCryptographyState,
) : HMAC {
    private val keyWrapper: (SecretKey) -> HMAC.Key = { key ->
        object : HMAC.Key, EncodableKey<HMAC.Key.Format> by JdkSecretEncodableKey(state, key) {
            private val signature = JdkMacSignature(state, key, key.algorithm)
            override fun signatureGenerator(): SignatureGenerator = signature
            override fun signatureVerifier(): SignatureVerifier = signature
        }
    }

    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        return JdkSecretKeyDecoder(state, "Hmac${digest.hashAlgorithmName()}", keyWrapper)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        return JdkSecretKeyGenerator(state, "Hmac${digest.hashAlgorithmName()}", keyWrapper)
    }
}
