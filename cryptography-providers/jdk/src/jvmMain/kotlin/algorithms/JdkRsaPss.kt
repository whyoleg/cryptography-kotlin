/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*
import java.util.concurrent.*

internal class JdkRsaPss(
    state: JdkCryptographyState,
) : JdkRsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(state), RSA.PSS {
    init {
        // not supported on Android
        val _ = state.signature("RSASSA-PSS")
    }

    override val wrapPublicKey: (JPublicKey, JdkRsaDigest) -> RSA.PSS.PublicKey = ::RsaPssPublicKey
    override val wrapPrivateKey: (JPrivateKey, JdkRsaDigest, RSA.PSS.PublicKey?) -> RSA.PSS.PrivateKey =
        ::RsaPssPrivateKey
    override val wrapKeyPair: (RSA.PSS.PublicKey, RSA.PSS.PrivateKey) -> RSA.PSS.KeyPair = ::RsaPssKeyPair

    private val digests = ConcurrentHashMap<CryptographyAlgorithmId<Digest>, JdkRsaDigest>()

    // PSS uses `Signature` configured with the digest, the salt size depends on the key, so it's resolved only on first use
    override fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): JdkRsaDigest = digests.getOrPut(digest) {
        val name = rsaHashAlgorithmName(digest)
        val digestSize = state.messageDigest(name).use { it.digestLength }
        state.signature("RSASSA-PSS").use { it.setParameter(pssParameters(name, digestSize)) }
        JdkRsaDigest(digest, name)
    }

    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private inner class RsaPssPublicKey(
        key: JPublicKey,
        digest: JdkRsaDigest,
    ) : RSA.PSS.PublicKey, RsaPublicEncodableKey(key, digest) {
        override fun signatureVerifier(): SignatureVerifier {
            val digestSize = state.messageDigest(digest.name).use { it.digestLength }
            return signatureVerifier(digestSize.bytes)
        }

        override fun signatureVerifier(saltSize: BinarySize): SignatureVerifier {
            return JdkSignatureVerifier(state, key, "RSASSA-PSS", pssParameters(digest.name, saltSize.inBytes))
        }
    }

    private inner class RsaPssPrivateKey(
        key: JPrivateKey,
        digest: JdkRsaDigest,
        publicKey: RSA.PSS.PublicKey?,
    ) : RSA.PSS.PrivateKey, RsaPrivateEncodableKey(key, digest, publicKey) {
        override fun signatureGenerator(): SignatureGenerator {
            val digestSize = state.messageDigest(digest.name).use { it.digestLength }
            return signatureGenerator(digestSize.bytes)
        }

        override fun signatureGenerator(saltSize: BinarySize): SignatureGenerator {
            return JdkSignatureGenerator(state, key, "RSASSA-PSS", pssParameters(digest.name, saltSize.inBytes))
        }
    }
}

private fun pssParameters(hashAlgorithmName: String, saltSize: Int): PSSParameterSpec =
    PSSParameterSpec(hashAlgorithmName, "MGF1", MGF1ParameterSpec(hashAlgorithmName), saltSize, 1)
