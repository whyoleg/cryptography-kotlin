/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoRsaPss : RSA.PSS {
    private val publicKeyFormat: (RSA.PublicKey.Format) -> String = {
        when (it) {
            RSA.PublicKey.Format.DER -> "spki"
            RSA.PublicKey.Format.PEM -> "pem-RSA-spki"
            RSA.PublicKey.Format.JWK -> "jwk"
            RSA.PublicKey.Format.DER_RSA,
            RSA.PublicKey.Format.PEM_RSA,
            -> error("$it format is not supported")
        }
    }
    private val privateKeyFormat: (RSA.PrivateKey.Format) -> String = {
        when (it) {
            RSA.PrivateKey.Format.DER -> "pkcs8"
            RSA.PrivateKey.Format.PEM -> "pem-RSA-pkcs8"
            RSA.PrivateKey.Format.JWK -> "jwk"
            RSA.PrivateKey.Format.DER_RSA,
            RSA.PrivateKey.Format.PEM_RSA,
            -> error("$it format is not supported")
        }
    }
    private val publicKeyWrapper: (CryptoKey) -> RSA.PSS.PublicKey = { key ->
        object : RSA.PSS.PublicKey, EncodableKey<RSA.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun signatureVerifier(): SignatureVerifier {
                return signatureVerifier(hashSize(key.algorithmName).bytes)
            }

            override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier = WebCryptoSignatureVerifier(
                algorithm = RsaPssSignatureAlgorithm(saltLength.inBytes),
                key = key
            )
        }
    }
    private val privateKeyWrapper: (CryptoKey) -> RSA.PSS.PrivateKey = { key ->
        object : RSA.PSS.PrivateKey, EncodableKey<RSA.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun signatureGenerator(): SignatureGenerator {
                return signatureGenerator(hashSize(key.algorithmName).bytes)
            }

            override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator = WebCryptoSignatureGenerator(
                algorithm = RsaPssSignatureAlgorithm(saltLength.inBytes),
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
            RsaKeyImportAlgorithm("RSA-PSS", digest.hashAlgorithmName()),
            arrayOf("verify"), publicKeyFormat, publicKeyWrapper
        )

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> =
        WebCryptoKeyDecoder(
            RsaKeyImportAlgorithm("RSA-PSS", digest.hashAlgorithmName()),
            arrayOf("sign"), privateKeyFormat, privateKeyWrapper
        )

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.PSS.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaKeyGenerationAlgorithm(
            name = "RSA-PSS",
            modulusLength = keySize.inBits,
            publicExponent = publicExponent.encodeToByteArray(),
            hash = digest.hashAlgorithmName()
        ),
        keyUsages = arrayOf("sign", "verify"),
        keyPairWrapper = keyPairWrapper
    )
}
