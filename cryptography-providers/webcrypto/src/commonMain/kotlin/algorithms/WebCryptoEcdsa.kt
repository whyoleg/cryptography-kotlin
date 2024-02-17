/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoEcdsa : WebCryptoEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>(
    algorithmName = "ECDSA",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf("verify"), ::EcdsaPublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("sign"), ::EcdsaPrivateKey),
    keyPairWrapper = ::EcdsaKeyPair
), ECDSA {
    private class EcdsaKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcdsaPublicKey(publicKey: CryptoKey) : EcPublicKey(publicKey), ECDSA.PublicKey {
        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
            check(format == ECDSA.SignatureFormat.RAW) { "Only RAW signature format is supported" }
            return WebCryptoSignatureVerifier(EcdsaSignatureAlgorithm(digest.hashAlgorithmName()), publicKey)
        }
    }

    private class EcdsaPrivateKey(privateKey: CryptoKey) : EcPrivateKey(privateKey), ECDSA.PrivateKey {
        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
            check(format == ECDSA.SignatureFormat.RAW) { "Only RAW signature format is supported" }
            return WebCryptoSignatureGenerator(EcdsaSignatureAlgorithm(digest.hashAlgorithmName()), privateKey)
        }
    }
}
