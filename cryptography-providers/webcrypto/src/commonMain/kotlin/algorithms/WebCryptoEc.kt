/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal sealed class WebCryptoEc<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>>(
    protected val algorithmName: String,
    private val publicKeyWrapper: WebCryptoKeyWrapper<PublicK>,
    private val privateKeyWrapper: WebCryptoKeyWrapper<PrivateK>,
    keyPairWrapper: (PublicK, PrivateK) -> KP,
) : EC<PublicK, PrivateK, KP> {
    private val keyPairUsages: Array<String> = publicKeyWrapper.usages + privateKeyWrapper.usages
    private val keyPairWrapper: (CryptoKeyPair) -> KP = {
        keyPairWrapper(publicKeyWrapper.wrap(it.publicKey), privateKeyWrapper.wrap(it.privateKey))
    }

    final override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, PublicK> = WebCryptoKeyDecoder(
        algorithm = EcKeyAlgorithm(algorithmName, curve.name),
        keyProcessor = EcPublicKeyProcessor,
        keyWrapper = publicKeyWrapper,
    )

    final override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, PrivateK> = WebCryptoKeyDecoder(
        algorithm = EcKeyAlgorithm(algorithmName, curve.name),
        keyProcessor = EcPrivateKeyProcessor,
        keyWrapper = privateKeyWrapper,
    )

    final override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<KP> = WebCryptoAsymmetricKeyGenerator(
        algorithm = EcKeyAlgorithm(algorithmName, curve.name),
        keyUsages = keyPairUsages,
        keyPairWrapper = keyPairWrapper
    )

    protected abstract class EcPublicKey(val publicKey: CryptoKey) : WebCryptoEncodableKey<EC.PublicKey.Format>(
        key = publicKey,
        keyProcessor = EcPublicKeyProcessor
    ), EC.PublicKey

    protected abstract class EcPrivateKey(val privateKey: CryptoKey) : WebCryptoEncodableKey<EC.PrivateKey.Format>(
        key = privateKey,
        keyProcessor = EcPrivateKeyProcessor
    ), EC.PrivateKey
}

private object EcPublicKeyProcessor : WebCryptoKeyProcessor<EC.PublicKey.Format>() {
    override fun stringFormat(format: EC.PublicKey.Format): String = when (format) {
        EC.PublicKey.Format.JWK -> "jwk"
        EC.PublicKey.Format.RAW,
        EC.PublicKey.Format.RAW.Compressed,
                                -> "raw"
        EC.PublicKey.Format.DER,
        EC.PublicKey.Format.PEM,
                                -> "spki"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EC.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> key
        EC.PublicKey.Format.RAW,
        EC.PublicKey.Format.RAW.Compressed,
                                -> key
        EC.PublicKey.Format.DER -> key
        EC.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, key)
    }

    override fun afterEncoding(format: EC.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> key
        EC.PublicKey.Format.RAW -> key
        EC.PublicKey.Format.RAW.Compressed
                                -> compressPublicKey(key)
        EC.PublicKey.Format.DER -> key
        EC.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, key)
    }

    private fun compressPublicKey(key: ByteArray): ByteArray {
        require(key[0] == 0x04.toByte() && key.size % 2 != 0) { "Invalid key format" }
        return key.copyOfRange(0, (key.size - 1) / 2 + 1).also {
            it[0] = if (key.last() % 2 == 0) 0x02 else 0x03
        }
    }
}

private object EcPrivateKeyProcessor : WebCryptoKeyProcessor<EC.PrivateKey.Format>() {
    override fun stringFormat(format: EC.PrivateKey.Format): String = when (format) {
        EC.PrivateKey.Format.JWK -> "jwk"
        EC.PrivateKey.Format.RAW,
        EC.PrivateKey.Format.DER,
        EC.PrivateKey.Format.PEM,
        EC.PrivateKey.Format.DER.SEC1,
        EC.PrivateKey.Format.PEM.SEC1,
                                 -> "pkcs8"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EC.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK      -> key
        EC.PrivateKey.Format.RAW      -> {
            val curveId = when (val namedCurve = algorithm.ecKeyAlgorithmNamedCurve) {
                EC.Curve.P256.name -> ObjectIdentifier.secp256r1
                EC.Curve.P384.name -> ObjectIdentifier.secp384r1
                EC.Curve.P521.name -> ObjectIdentifier.secp521r1
                else               -> error("Unknown curve: $namedCurve")
            }
            wrapPrivateKeyInfo(
                version = 0,
                identifier = EcKeyAlgorithmIdentifier(EcParameters(curveId)),
                key = Der.encodeToByteArray(EcPrivateKey.serializer(), EcPrivateKey(version = 1, key))
            )
        }
        EC.PrivateKey.Format.DER      -> key
        EC.PrivateKey.Format.PEM      -> unwrapPem(PemLabel.PrivateKey, key)
        EC.PrivateKey.Format.DER.SEC1 -> convertEcPrivateKeyFromSec1ToPkcs8(key)
        EC.PrivateKey.Format.PEM.SEC1 -> convertEcPrivateKeyFromSec1ToPkcs8(unwrapPem(PemLabel.EcPrivateKey, key))
    }

    override fun afterEncoding(format: EC.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK      -> key
        EC.PrivateKey.Format.RAW      -> {
            Der.decodeFromByteArray(
                EcPrivateKey.serializer(),
                unwrapPrivateKeyInfo(ObjectIdentifier.EC, key)
            ).privateKey
        }
        EC.PrivateKey.Format.DER      -> key
        EC.PrivateKey.Format.PEM      -> wrapPem(PemLabel.PrivateKey, key)
        EC.PrivateKey.Format.DER.SEC1 -> convertEcPrivateKeyFromPkcs8ToSec1(key)
        EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, convertEcPrivateKeyFromPkcs8ToSec1(key))
    }
}
