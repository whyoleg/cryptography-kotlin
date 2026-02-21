/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.interfaces.*

internal class JdkEcdsa(state: JdkCryptographyState) : JdkEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>(state), ECDSA {
    override val wrapPublicKey: (JPublicKey) -> ECDSA.PublicKey = ::EcdsaPublicKey
    override val wrapPrivateKey: (JPrivateKey, ECDSA.PublicKey?) -> ECDSA.PrivateKey = ::EcdsaPrivateKey
    override val wrapKeyPair: (ECDSA.PublicKey, ECDSA.PrivateKey) -> ECDSA.KeyPair = ::EcdsaKeyPair

    private class EcdsaKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private inner class EcdsaPublicKey(
        key: JPublicKey,
    ) : ECDSA.PublicKey, BaseEcPublicKey(key) {
        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>?, format: ECDSA.SignatureFormat): SignatureVerifier {
            val verifier = JdkSignatureVerifier(state, key, digest.hashECAlgorithmName() + "withECDSA", null)
            return when (format) {
                ECDSA.SignatureFormat.DER -> verifier
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(verifier, (key as ECKey).params.curveOrderSize())
            }
        }
    }

    private inner class EcdsaPrivateKey(
        key: JPrivateKey,
        publicKey: ECDSA.PublicKey?,
    ) : ECDSA.PrivateKey, BaseEcPrivateKey(key, publicKey) {
        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>?, format: ECDSA.SignatureFormat): SignatureGenerator {
            val generator = JdkSignatureGenerator(state, key, digest.hashECAlgorithmName() + "withECDSA", null)
            return when (format) {
                ECDSA.SignatureFormat.DER -> generator
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(generator, (key as ECKey).params.curveOrderSize())
            }
        }
    }
}
