/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*

internal class JdkRsaPss(
    state: JdkCryptographyState,
) : JdkRsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(state), RSA.PSS {
    override val wrapPublicKey: (JPublicKey, String) -> RSA.PSS.PublicKey = ::RsaPssPublicKey
    override val wrapPrivateKey: (JPrivateKey, String, RSA.PSS.PublicKey?) -> RSA.PSS.PrivateKey = ::RsaPssPrivateKey
    override val wrapKeyPair: (RSA.PSS.PublicKey, RSA.PSS.PrivateKey) -> RSA.PSS.KeyPair = ::RsaPssKeyPair

    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private inner class RsaPssPublicKey(
        key: JPublicKey,
        private val hashAlgorithmName: String,
    ) : RSA.PSS.PublicKey, RsaPublicEncodableKey(key) {
        override fun signatureVerifier(): SignatureVerifier {
            val digestSize = state.messageDigest(hashAlgorithmName).use { it.digestLength }
            return signatureVerifier(digestSize.bytes)
        }

        override fun signatureVerifier(saltSize: BinarySize): SignatureVerifier {
            val parameters = PSSParameterSpec(
                hashAlgorithmName,
                "MGF1",
                MGF1ParameterSpec(hashAlgorithmName),
                saltSize.inBytes,
                1
            )
            return JdkSignatureVerifier(state, key, "RSASSA-PSS", parameters)
        }
    }

    private inner class RsaPssPrivateKey(
        key: JPrivateKey,
        hashAlgorithmName: String,
        publicKey: RSA.PSS.PublicKey?,
    ) : RSA.PSS.PrivateKey, RsaPrivateEncodableKey(key, hashAlgorithmName, publicKey) {
        override fun signatureGenerator(): SignatureGenerator {
            val digestSize = state.messageDigest(hashAlgorithmName).use { it.digestLength }
            return signatureGenerator(digestSize.bytes)
        }

        override fun signatureGenerator(saltSize: BinarySize): SignatureGenerator {
            val parameters = PSSParameterSpec(
                hashAlgorithmName,
                "MGF1",
                MGF1ParameterSpec(hashAlgorithmName),
                saltSize.inBytes,
                1
            )
            return JdkSignatureGenerator(state, key, "RSASSA-PSS", parameters)
        }
    }
}
