package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.ec.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*
import dev.whyoleg.cryptography.webcrypto.operations.*

internal object WebCryptoEcdsa : ECDSA, WebCryptoEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>("ECDSA") {
    override val publicKeyWrapper: (CryptoKey) -> ECDSA.PublicKey = { key ->
        object : ECDSA.PublicKey, EncodableKey<EC.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>): SignatureVerifier =
                WebCryptoSignatureVerifier(EcdsaParams(digest.hashAlgorithmName()), key, 0)
        }
    }
    override val privateKeyWrapper: (CryptoKey) -> ECDSA.PrivateKey = { key ->
        object : ECDSA.PrivateKey, EncodableKey<EC.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>): SignatureGenerator =
                WebCryptoSignatureGenerator(EcdsaParams(digest.hashAlgorithmName()), key, 0)
        }
    }
    override val keyPairWrapper: (CryptoKeyPair) -> ECDSA.KeyPair = { keyPair ->
        object : ECDSA.KeyPair {
            override val publicKey: ECDSA.PublicKey = publicKeyWrapper(keyPair.publicKey)
            override val privateKey: ECDSA.PrivateKey = privateKeyWrapper(keyPair.privateKey)
        }
    }
}
