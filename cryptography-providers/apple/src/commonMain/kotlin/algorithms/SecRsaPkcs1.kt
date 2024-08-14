/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import platform.Security.*

internal object SecRsaPkcs1 : SecRsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(), RSA.PKCS1 {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaPkcs1SecKeyAlgorithm()

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.PKCS1.KeyPair = RsaPkcs1KeyPair(
        publicKey = RsaPkcs1PublicKey(publicKey, algorithm),
        privateKey = RsaPkcs1PrivateKey(privateKey, algorithm),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PKCS1.PublicKey = RsaPkcs1PublicKey(key, algorithm)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PKCS1.PrivateKey = RsaPkcs1PrivateKey(key, algorithm)

    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(
        publicKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = SecSignatureVerifier(publicKey, algorithm)
        override fun encryptor(): Encryptor = RsaPkcs1Encryptor(publicKey)
    }

    private class RsaPkcs1PrivateKey(
        privateKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPrivateKey(privateKey), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = SecSignatureGenerator(privateKey, algorithm)
        override fun decryptor(): Decryptor = RsaPkcs1Decryptor(privateKey)
    }
}

private class RsaPkcs1Encryptor(private val publicKey: SecKeyRef) : Encryptor {
    override fun encryptBlocking(plaintext: ByteArray): ByteArray {
        return secEncrypt(publicKey, kSecKeyAlgorithmRSAEncryptionPKCS1, plaintext)
    }
}

private class RsaPkcs1Decryptor(private val privateKey: SecKeyRef) : Decryptor {
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray {
        return secDecrypt(privateKey, kSecKeyAlgorithmRSAEncryptionPKCS1, ciphertext)
    }
}
