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

internal object SecRsaPkcs1 : SecRsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(
    wrapPublicKey = ::RsaPkcs1PublicKey,
    wrapPrivateKey = ::RsaPkcs1PrivateKey,
    wrapKeyPair = ::RsaPkcs1KeyPair,
), RSA.PKCS1 {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaPkcs1SecKeyAlgorithm()

    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(
        publicKey: SecKeyRef,
        digest: CryptographyAlgorithmId<Digest>,
    ) : RsaPublicKey(publicKey, digest), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = SecSignatureVerifier(publicKey, hashAlgorithm(digest))
        override fun encryptor(): Encryptor = RsaPkcs1Encryptor(publicKey)
    }

    private class RsaPkcs1PrivateKey(
        privateKey: SecKeyRef,
        digest: CryptographyAlgorithmId<Digest>,
        publicKey: RSA.PKCS1.PublicKey?,
    ) : RsaPrivateKey(privateKey, digest, publicKey), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = SecSignatureGenerator(privateKey, hashAlgorithm(digest))
        override fun decryptor(): Decryptor = RsaPkcs1Decryptor(privateKey)
    }
}

private class RsaPkcs1Encryptor(private val publicKey: SecKeyRef) : BaseEncryptor {
    override fun createEncryptFunction(): CipherFunction {
        return SecCipherFunction(publicKey, kSecKeyAlgorithmRSAEncryptionPKCS1, ::SecKeyCreateEncryptedData)
    }
}

private class RsaPkcs1Decryptor(private val privateKey: SecKeyRef) : BaseDecryptor {
    override fun createDecryptFunction(): CipherFunction {
        return SecCipherFunction(privateKey, kSecKeyAlgorithmRSAEncryptionPKCS1, ::SecKeyCreateDecryptedData)
    }
}
