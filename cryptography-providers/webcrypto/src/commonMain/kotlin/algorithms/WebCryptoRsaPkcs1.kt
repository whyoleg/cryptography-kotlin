/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoRsaPkcs1 : WebCryptoRsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(
    algorithmName = "RSASSA-PKCS1-v1_5",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf("verify"), ::RsaPkcs1PublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("sign"), ::RsaPkcs1PrivateKey),
    keyPairWrapper = ::RsaPkcs1KeyPair
), RSA.PKCS1 {
    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(publicKey: CryptoKey) : RsaPublicKey(publicKey), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = WebCryptoSignatureVerifier(Algorithm(algorithmName), publicKey)
        override fun encryptor(): Encryptor = error("RSA-PKCS1 encryption is not supported by WebCrypto")
    }

    private class RsaPkcs1PrivateKey(privateKey: CryptoKey) : RsaPrivateKey(privateKey), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = WebCryptoSignatureGenerator(Algorithm(algorithmName), privateKey)
        override fun decryptor(): Decryptor = error("RSA-PKCS1 decryption is not supported by WebCrypto")
    }
}
