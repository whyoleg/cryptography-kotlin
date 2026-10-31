/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.*
import platform.Security.*

internal object SecRsaPss : SecRsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(
    wrapPublicKey = ::RsaPssPublicKey,
    wrapPrivateKey = ::RsaPssPrivateKey,
    wrapKeyPair = ::RsaPssKeyPair,
), RSA.PSS {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaPssSecKeyAlgorithm()

    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(
        publicKey: SecKey,
        digest: SecRsaDigest,
    ) : RsaPublicKey(publicKey, digest), RSA.PSS.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = SecSignatureVerifier(publicKey, digest.algorithm)
        override fun signatureVerifier(saltSize: BinarySize): SignatureVerifier = unsupportedParameter("salt size", saltSize)
    }

    private class RsaPssPrivateKey(
        privateKey: SecKey,
        digest: SecRsaDigest,
        publicKey: RSA.PSS.PublicKey?,
    ) : RsaPrivateKey(privateKey, digest, publicKey), RSA.PSS.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = SecSignatureGenerator(privateKey, digest.algorithm)
        override fun signatureGenerator(saltSize: BinarySize): SignatureGenerator = unsupportedParameter("salt size", saltSize)
    }
}
