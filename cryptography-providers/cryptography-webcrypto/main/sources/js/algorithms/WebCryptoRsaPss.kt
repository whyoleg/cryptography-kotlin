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
    private val keyUsages = arrayOf("sign", "verify")
    private val publicKeyFormat: (RSA.PublicKey.Format) -> String = {
        when (it) {
            RSA.PublicKey.Format.DER -> "spki"
            RSA.PublicKey.Format.JWK -> "jwk"
            RSA.PublicKey.Format.PEM -> TODO("PEM format is not supported yet")
        }
    }
    private val privateKeyFormat: (RSA.PrivateKey.Format) -> String = {
        when (it) {
            RSA.PrivateKey.Format.DER -> "pkcs8"
            RSA.PrivateKey.Format.JWK -> "jwk"
            RSA.PrivateKey.Format.PEM -> TODO("PEM format is not supported yet")
        }
    }
    private val publicKeyWrapper: (CryptoKey) -> RSA.PSS.PublicKey = { key ->
        object : RSA.PSS.PublicKey, EncodableKey<RSA.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier = WebCryptoSignatureVerifier(
                algorithm = RsaPssParams(saltLength.bytes),
                key = key,
                signatureSize = hashAlgorithmDigestSize(key.algorithm.unsafeCast<RsaHashedKeyImportAlgorithm>().hash)
            )
        }
    }
    private val privateKeyWrapper: (CryptoKey) -> RSA.PSS.PrivateKey = { key ->
        object : RSA.PSS.PrivateKey, EncodableKey<RSA.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator = WebCryptoSignatureGenerator(
                algorithm = RsaPssParams(saltLength.bytes),
                key = key,
                signatureSize = hashAlgorithmDigestSize(key.algorithm.unsafeCast<RsaHashedKeyImportAlgorithm>().hash)
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
            keyUsages, publicKeyFormat, publicKeyWrapper
        )

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSA-PSS", digest.hashAlgorithmName()),
            keyUsages, privateKeyFormat, privateKeyWrapper
        )

    override fun keyPairGenerator(
        keySize: BinarySize,
        publicExponent: RSA.PublicExponent,
        digest: CryptographyAlgorithmId<Digest>,
    ): KeyGenerator<RSA.PSS.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaHashedKeyGenerationAlgorithm(
            name = "RSA-PSS",
            modulusLength = keySize.bits,
            publicExponent = when (publicExponent) {
                RSA.PublicExponent.F4        -> byteArrayOf(0x01, 0x00, 0x01)
                is RSA.PublicExponent.Bytes  -> publicExponent.value
                is RSA.PublicExponent.Number -> TODO("not yet supported")
                is RSA.PublicExponent.Text   -> TODO("not yet supported")
            },
            digest.hashAlgorithmName()
        ),
        keyUsages = keyUsages,
        keyPairWrapper = keyPairWrapper
    )
}
