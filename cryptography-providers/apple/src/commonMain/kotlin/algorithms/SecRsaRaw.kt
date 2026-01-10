/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.operations.*
import platform.Security.*

internal object SecRsaRaw : SecRsa<RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair>(
    wrapPublicKey = ::RsaRawPublicKey,
    wrapPrivateKey = ::RsaRawPrivateKey,
    wrapKeyPair = ::RsaRawKeyPair,
), RSA.RAW {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = null

    private class RsaRawKeyPair(
        override val publicKey: RSA.RAW.PublicKey,
        override val privateKey: RSA.RAW.PrivateKey,
    ) : RSA.RAW.KeyPair

    private class RsaRawPublicKey(
        publicKey: SecKeyRef,
        @Suppress("unused") algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.RAW.PublicKey {
        override fun encryptor(): Encryptor = RsaRawEncryptor(publicKey)
    }

    private class RsaRawPrivateKey(
        privateKey: SecKeyRef,
        @Suppress("unused") algorithm: SecKeyAlgorithm?,
        publicKey: RSA.RAW.PublicKey?,
    ) : RsaPrivateKey(privateKey, algorithm, publicKey), RSA.RAW.PrivateKey {
        override fun decryptor(): Decryptor = RsaRawDecryptor(privateKey)
    }
}

private class RsaRawEncryptor(private val publicKey: SecKeyRef) : BaseEncryptor {
    override fun createEncryptFunction(): CipherFunction {
        return SecCipherFunction(publicKey, kSecKeyAlgorithmRSAEncryptionRaw, ::SecKeyCreateEncryptedData)
    }
}

private class RsaRawDecryptor(private val privateKey: SecKeyRef) : BaseDecryptor {
    override fun createDecryptFunction(): CipherFunction {
        return SecCipherFunction(privateKey, kSecKeyAlgorithmRSAEncryptionRaw, ::SecKeyCreateDecryptedData)
    }
}
