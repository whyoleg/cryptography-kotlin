/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
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
        EC.PublicKey.Format.RAW -> "raw"
        EC.PublicKey.Format.DER,
        EC.PublicKey.Format.PEM,
                                -> "spki"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EC.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> key
        EC.PublicKey.Format.RAW -> key
        EC.PublicKey.Format.DER -> key
        EC.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, key)
    }

    override fun afterEncoding(format: EC.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> key
        EC.PublicKey.Format.RAW -> key
        EC.PublicKey.Format.DER -> key
        EC.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, key)
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
        EC.PrivateKey.Format.RAW -> {
            val curveId = when (val namedCurve = algorithm.ecKeyAlgorithmNamedCurve) {
                EC.Curve.P256.name -> ObjectIdentifier.secp256r1
                EC.Curve.P384.name -> ObjectIdentifier.secp384r1
                EC.Curve.P521.name -> ObjectIdentifier.secp521r1
                else               -> error("Unknown curve: $namedCurve")
            }
            wrapPrivateKey(
                version = 0,
                identifier = EcKeyAlgorithmIdentifier(EcParameters(curveId)),
                key = Der.encodeToByteArray(EcPrivateKey.serializer(), EcPrivateKey(version = 1, key))
            )
        }
        EC.PrivateKey.Format.DER      -> key
        EC.PrivateKey.Format.PEM      -> unwrapPem(PemLabel.PrivateKey, key)
        EC.PrivateKey.Format.DER.SEC1 -> convertSec1ToPkcs8(key)
        EC.PrivateKey.Format.PEM.SEC1 -> convertSec1ToPkcs8(unwrapPem(PemLabel.EcPrivateKey, key))
    }

    override fun afterEncoding(format: EC.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK      -> key
        EC.PrivateKey.Format.RAW -> {
            Der.decodeFromByteArray(
                EcPrivateKey.serializer(),
                unwrapPrivateKey(ObjectIdentifier.EC, key)
            ).privateKey
        }
        EC.PrivateKey.Format.DER      -> key
        EC.PrivateKey.Format.PEM      -> wrapPem(PemLabel.PrivateKey, key)
        EC.PrivateKey.Format.DER.SEC1 -> convertPkcs8ToSec1(key)
        EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, convertPkcs8ToSec1(key))
    }

    private fun convertPkcs8ToSec1(input: ByteArray): ByteArray {
        val privateKeyInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)

        val privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm
        check(privateKeyAlgorithm is EcKeyAlgorithmIdentifier) {
            "Expected algorithm '${ObjectIdentifier.EC}', received: '${privateKeyAlgorithm.algorithm}'"
        }
        // the produced key could not contain parameters in underlying EcPrivateKey,
        // but they are available in `privateKeyAlgorithm`
        val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), privateKeyInfo.privateKey)
        if (ecPrivateKey.parameters != null) return privateKeyInfo.privateKey

        val enhancedEcPrivateKey = EcPrivateKey(
            version = ecPrivateKey.version,
            privateKey = ecPrivateKey.privateKey,
            parameters = privateKeyAlgorithm.parameters,
            publicKey = ecPrivateKey.publicKey
        )
        return Der.encodeToByteArray(EcPrivateKey.serializer(), enhancedEcPrivateKey)
    }

    private fun convertSec1ToPkcs8(input: ByteArray): ByteArray {
        val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), input)

        checkNotNull(ecPrivateKey.parameters) { "EC Parameters are not present in the key" }

        val privateKeyInfo = PrivateKeyInfo(
            version = 0,
            privateKeyAlgorithm = EcKeyAlgorithmIdentifier(ecPrivateKey.parameters),
            privateKey = input
        )
        return Der.encodeToByteArray(PrivateKeyInfo.serializer(), privateKeyInfo)
    }
}
