/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal abstract class WebCryptoRsa<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>>(
    protected val algorithmName: String,
    private val publicKeyWrapper: WebCryptoKeyWrapper<PublicK>,
    private val privateKeyWrapper: WebCryptoKeyWrapper<PrivateK>,
    keyPairWrapper: (PublicK, PrivateK) -> KP,
) : RSA<PublicK, PrivateK, KP> {
    private val keyPairUsages: Array<String> = publicKeyWrapper.usages + privateKeyWrapper.usages
    private val keyPairWrapper: (CryptoKeyPair) -> KP = {
        keyPairWrapper(publicKeyWrapper.wrap(it.publicKey), privateKeyWrapper.wrap(it.privateKey))
    }

    final override fun publicKeyDecoder(
        digest: CryptographyAlgorithmId<Digest>,
    ): KeyDecoder<RSA.PublicKey.Format, PublicK> = WebCryptoKeyDecoder(
        algorithm = RsaKeyImportAlgorithm(algorithmName, digest.hashAlgorithmName()),
        keyProcessor = RsaPublicKeyProcessor,
        keyWrapper = publicKeyWrapper
    )

    final override fun privateKeyDecoder(
        digest: CryptographyAlgorithmId<Digest>,
    ): KeyDecoder<RSA.PrivateKey.Format, PrivateK> = WebCryptoKeyDecoder(
        algorithm = RsaKeyImportAlgorithm(algorithmName, digest.hashAlgorithmName()),
        keyProcessor = RsaPrivateKeyProcessor,
        keyWrapper = privateKeyWrapper,
    )

    final override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<KP> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaKeyGenerationAlgorithm(
            name = algorithmName,
            modulusLength = keySize.inBits,
            publicExponent = publicExponent.encodeToByteArray(),
            hash = digest.hashAlgorithmName()
        ),
        keyUsages = keyPairUsages,
        keyPairWrapper = keyPairWrapper
    )

    protected abstract class RsaPublicKey(protected val publicKey: CryptoKey) : WebCryptoEncodableKey<RSA.PublicKey.Format>(
        key = publicKey,
        keyProcessor = RsaPublicKeyProcessor
    ), RSA.PublicKey

    protected abstract class RsaPrivateKey(protected val privateKey: CryptoKey) : WebCryptoEncodableKey<RSA.PrivateKey.Format>(
        key = privateKey,
        keyProcessor = RsaPrivateKeyProcessor
    ), RSA.PrivateKey
}

private object RsaPublicKeyProcessor : WebCryptoKeyProcessor<RSA.PublicKey.Format>() {
    override fun stringFormat(format: RSA.PublicKey.Format): String = when (format) {
        RSA.PublicKey.Format.JWK -> "jwk"
        RSA.PublicKey.Format.DER,
        RSA.PublicKey.Format.PEM,
        RSA.PublicKey.Format.DER.PKCS1,
        RSA.PublicKey.Format.PEM.PKCS1,
                                 -> "spki"
    }

    override fun beforeDecoding(format: RSA.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        RSA.PublicKey.Format.JWK       -> key
        RSA.PublicKey.Format.DER       -> key
        RSA.PublicKey.Format.PEM       -> unwrapPem(PemLabel.PublicKey, key)
        RSA.PublicKey.Format.DER.PKCS1 -> wrapPublicKey(RsaKeyAlgorithmIdentifier, key)
        RSA.PublicKey.Format.PEM.PKCS1 -> wrapPublicKey(RsaKeyAlgorithmIdentifier, unwrapPem(PemLabel.RsaPublicKey, key))
    }

    override fun afterEncoding(format: RSA.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        RSA.PublicKey.Format.JWK       -> key
        RSA.PublicKey.Format.DER       -> key
        RSA.PublicKey.Format.PEM       -> wrapPem(PemLabel.PublicKey, key)
        RSA.PublicKey.Format.DER.PKCS1 -> unwrapPublicKey(ObjectIdentifier.RSA, key)
        RSA.PublicKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPublicKey, unwrapPublicKey(ObjectIdentifier.RSA, key))
    }
}

private object RsaPrivateKeyProcessor : WebCryptoKeyProcessor<RSA.PrivateKey.Format>() {
    override fun stringFormat(format: RSA.PrivateKey.Format): String = when (format) {
        RSA.PrivateKey.Format.JWK -> "jwk"
        RSA.PrivateKey.Format.DER,
        RSA.PrivateKey.Format.PEM,
        RSA.PrivateKey.Format.DER.PKCS1,
        RSA.PrivateKey.Format.PEM.PKCS1,
                                  -> "pkcs8"
    }

    override fun beforeDecoding(format: RSA.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        RSA.PrivateKey.Format.JWK       -> key
        RSA.PrivateKey.Format.DER       -> key
        RSA.PrivateKey.Format.PEM       -> unwrapPem(PemLabel.PrivateKey, key)
        RSA.PrivateKey.Format.DER.PKCS1 -> wrapPrivateKey(0, RsaKeyAlgorithmIdentifier, key)
        RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPrivateKey(0, RsaKeyAlgorithmIdentifier, unwrapPem(PemLabel.RsaPrivateKey, key))
    }

    override fun afterEncoding(format: RSA.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        RSA.PrivateKey.Format.JWK       -> key
        RSA.PrivateKey.Format.DER       -> key
        RSA.PrivateKey.Format.PEM       -> wrapPem(PemLabel.PrivateKey, key)
        RSA.PrivateKey.Format.DER.PKCS1 -> unwrapPrivateKey(ObjectIdentifier.RSA, key)
        RSA.PrivateKey.Format.PEM.PKCS1 -> wrapPem(PemLabel.RsaPrivateKey, unwrapPrivateKey(ObjectIdentifier.RSA, key))
    }
}
