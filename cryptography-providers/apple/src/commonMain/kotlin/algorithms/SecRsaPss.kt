/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import platform.Security.*

internal object SecRsaPss : SecRsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(), RSA.PSS {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaPssSecKeyAlgorithm()

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.PSS.KeyPair = RsaPssKeyPair(
        publicKey = RsaPssPublicKey(publicKey, algorithm),
        privateKey = RsaPssPrivateKey(privateKey, algorithm),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PSS.PublicKey = RsaPssPublicKey(key, algorithm)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PSS.PrivateKey = RsaPssPrivateKey(key, algorithm)

    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(
        publicKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.PSS.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = SecSignatureVerifier(publicKey, algorithm)
        override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier = error("custom saltLength is not supported")
    }

    private class RsaPssPrivateKey(
        privateKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPrivateKey(privateKey), RSA.PSS.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = SecSignatureGenerator(privateKey, algorithm)
        override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator = error("custom saltLength is not supported")
    }
}
