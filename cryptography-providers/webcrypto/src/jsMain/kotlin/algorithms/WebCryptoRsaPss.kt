package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*
import dev.whyoleg.cryptography.webcrypto.operations.*

internal object WebCryptoRsaPss : RSA.PSS {
    private val publicKeyFormat: (RSA.PublicKey.Format) -> String = {
        when (it) {
            RSA.PublicKey.Format.DER -> "spki"
            RSA.PublicKey.Format.PEM -> "pem-RSA-spki"
            RSA.PublicKey.Format.JWK -> "jwk"
        }
    }
    private val privateKeyFormat: (RSA.PrivateKey.Format) -> String = {
        when (it) {
            RSA.PrivateKey.Format.DER -> "pkcs8"
            RSA.PrivateKey.Format.PEM -> "pem-RSA-pkcs8"
            RSA.PrivateKey.Format.JWK -> "jwk"
        }
    }
    private val publicKeyWrapper: (CryptoKey) -> RSA.PSS.PublicKey = { key ->
        object : RSA.PSS.PublicKey, EncodableKey<RSA.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier = WebCryptoSignatureVerifier(
                algorithm = RsaPssParams(saltLength.inBytes),
                key = key
            )
        }
    }
    private val privateKeyWrapper: (CryptoKey) -> RSA.PSS.PrivateKey = { key ->
        object : RSA.PSS.PrivateKey, EncodableKey<RSA.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator = WebCryptoSignatureGenerator(
                algorithm = RsaPssParams(saltLength.inBytes),
                key = key
            )
        }
    }
    private val keyPairWrapper: (CryptoKeyPair) -> RSA.PSS.KeyPair = { keyPair ->
        object : RSA.PSS.KeyPair {
            override val publicKey: RSA.PSS.PublicKey = publicKeyWrapper(keyPair.publicKey)
            override val privateKey: RSA.PSS.PrivateKey = privateKeyWrapper(keyPair.privateKey)
        }
    }

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PSS.PublicKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSA-PSS", digest.hashAlgorithmName()),
            arrayOf("verify"), publicKeyFormat, publicKeyWrapper
        )

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSA-PSS", digest.hashAlgorithmName()),
            arrayOf("sign"), privateKeyFormat, privateKeyWrapper
        )

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: RSA.PublicExponent,
    ): KeyGenerator<RSA.PSS.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaHashedKeyGenerationAlgorithm(
            name = "RSA-PSS",
            modulusLength = keySize.inBits,
            publicExponent = when (publicExponent) {
                RSA.PublicExponent.F4                                    -> byteArrayOf(0x01, 0x00, 0x01)
                is RSA.PublicExponent.Bytes                              -> publicExponent.value
                is RSA.PublicExponent.Number, is RSA.PublicExponent.Text ->
                    throw IllegalArgumentException("WebCrypto supports only F4 or Bytes public exponent")
            },
            digest.hashAlgorithmName()
        ),
        keyUsages = arrayOf("sign", "verify"),
        keyPairWrapper = keyPairWrapper
    )
}
