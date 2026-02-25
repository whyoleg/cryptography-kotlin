/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.operations.*
import platform.Security.*

internal object SecRsaOaep : SecRsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(
    wrapPublicKey = ::RsaOaepPublicKey,
    wrapPrivateKey = ::RsaOaepPrivateKey,
    wrapKeyPair = ::RsaOaepKeyPair,
), RSA.OAEP {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaOaepSecKeyAlgorithm()

    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(
        publicKey: SecKeyRef,
        digest: CryptographyAlgorithmId<Digest>,
    ) : RsaPublicKey(publicKey, digest), RSA.OAEP.PublicKey {
        override fun encryptor(): AuthenticatedEncryptor = RsaOaepEncryptor(publicKey, hashAlgorithm(digest))
    }

    private class RsaOaepPrivateKey(
        privateKey: SecKeyRef,
        digest: CryptographyAlgorithmId<Digest>,
        publicKey: RSA.OAEP.PublicKey?,
    ) : RsaPrivateKey(privateKey, digest, publicKey), RSA.OAEP.PrivateKey {
        override fun decryptor(): AuthenticatedDecryptor = RsaOaepDecryptor(privateKey, hashAlgorithm(digest))
    }
}

private class RsaOaepEncryptor(private val publicKey: SecKeyRef, private val algorithm: SecKeyAlgorithm?) : BaseAuthenticatedEncryptor {
    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        require(associatedData == null) { "Associated data inclusion is not supported" }

        return SecCipherFunction(publicKey, algorithm, ::SecKeyCreateEncryptedData)
    }
}

private class RsaOaepDecryptor(private val privateKey: SecKeyRef, private val algorithm: SecKeyAlgorithm?) : BaseAuthenticatedDecryptor {
    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        require(associatedData == null) { "Associated data inclusion is not supported" }

        return SecCipherFunction(privateKey, algorithm, ::SecKeyCreateDecryptedData)
    }
}
