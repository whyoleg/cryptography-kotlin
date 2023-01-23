package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*
import dev.whyoleg.cryptography.webcrypto.operations.*

internal object WebCryptoEcdsa : ECDSA, WebCryptoEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>("ECDSA") {
    override val publicKeyUsages: Array<String> get() = arrayOf("verify")
    override val privateKeyUsages: Array<String> get() = arrayOf("sign")
    override val keyPairUsages: Array<String> get() = arrayOf("sign", "verify")
    override val publicKeyWrapper: (CryptoKey) -> ECDSA.PublicKey = { key ->
        object : ECDSA.PublicKey, EncodableKey<EC.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
                check(format == ECDSA.SignatureFormat.RAW) { "Only RAW signature format is supported" }
                return WebCryptoSignatureVerifier(EcdsaParams(digest.hashAlgorithmName()), key)
            }
        }
    }
    override val privateKeyWrapper: (CryptoKey) -> ECDSA.PrivateKey = { key ->
        object : ECDSA.PrivateKey, EncodableKey<EC.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
                check(format == ECDSA.SignatureFormat.RAW) { "Only RAW signature format is supported" }
                return WebCryptoSignatureGenerator(EcdsaParams(digest.hashAlgorithmName()), key)
            }
        }
    }
    override val keyPairWrapper: (CryptoKeyPair) -> ECDSA.KeyPair = { keyPair ->
        object : ECDSA.KeyPair {
            override val publicKey: ECDSA.PublicKey = publicKeyWrapper(keyPair.publicKey)
            override val privateKey: ECDSA.PrivateKey = privateKeyWrapper(keyPair.privateKey)
        }
    }
}
