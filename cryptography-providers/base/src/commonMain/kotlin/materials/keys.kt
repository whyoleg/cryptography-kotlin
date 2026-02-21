/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.materials

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.unsafe.*
import kotlinx.serialization.builtins.*

@OptIn(UnsafeByteStringApi::class)
@CryptographyProviderApi
public fun unwrapPem(label: PemLabel, key: ByteArray): ByteArray {
    val document = PemDocument.decode(key)
    check(document.label == label) { "Wrong PEM label, expected $label, actual ${document.label}" }
    UnsafeByteStringOperations.withByteArrayUnsafe(document.content) { return it }
}

@OptIn(UnsafeByteStringApi::class)
@CryptographyProviderApi
public fun wrapPem(label: PemLabel, key: ByteArray): ByteArray {
    val document = PemDocument(label, UnsafeByteStringOperations.wrapUnsafe(key))
    return document.encodeToByteArray()
}

@CryptographyProviderApi
public fun unwrapSubjectPublicKeyInfo(algorithm: ObjectIdentifier, key: ByteArray): ByteArray {
    return Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), key).also {
        check(it.algorithm.algorithm == algorithm) { "Expected algorithm '${algorithm.value}', received: '${it.algorithm.algorithm}'" }
    }.subjectPublicKey.byteArray
}

@CryptographyProviderApi
public fun wrapSubjectPublicKeyInfo(identifier: AlgorithmIdentifier, key: ByteArray): ByteArray {
    return Der.encodeToByteArray(
        SubjectPublicKeyInfo.serializer(),
        SubjectPublicKeyInfo(identifier, BitArray(0, key))
    )
}

@CryptographyProviderApi
public fun unwrapPrivateKeyInfo(algorithm: ObjectIdentifier, key: ByteArray): ByteArray {
    return Der.decodeFromByteArray(PrivateKeyInfo.serializer(), key).also {
        check(it.privateKeyAlgorithm.algorithm == algorithm) { "Expected algorithm '${algorithm.value}', received: '${it.privateKeyAlgorithm.algorithm}'" }
    }.privateKey
}

@CryptographyProviderApi
public fun wrapPrivateKeyInfo(version: Int, identifier: AlgorithmIdentifier, key: ByteArray): ByteArray {
    return Der.encodeToByteArray(
        PrivateKeyInfo.serializer(),
        PrivateKeyInfo(version, identifier, key)
    )
}

// https://datatracker.ietf.org/doc/html/rfc8410#section-7
// For EdDSA/XDH, the private key is wrapped in an OCTET STRING within PKCS#8 (`CurvePrivateKey ::= OCTET STRING`)
@CryptographyProviderApi
public fun unwrapCurvePrivateKeyInfo(algorithm: ObjectIdentifier, key: ByteArray): ByteArray {
    val curvePrivateKey = unwrapPrivateKeyInfo(algorithm, key)
    return Der.decodeFromByteArray(ByteArraySerializer(), curvePrivateKey)
}

@CryptographyProviderApi
public fun wrapCurvePrivateKeyInfo(version: Int, identifier: AlgorithmIdentifier, key: ByteArray): ByteArray {
    val curvePrivateKey = Der.encodeToByteArray(ByteArraySerializer(), key)
    return wrapPrivateKeyInfo(version, identifier, curvePrivateKey)
}

// EC

@CryptographyProviderApi
public fun convertEcPrivateKeyFromPkcs8ToSec1(input: ByteArray): ByteArray {
    val privateKeyInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)

    val privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm
    check(privateKeyAlgorithm is EcAlgorithmIdentifier) {
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

@CryptographyProviderApi
public fun convertEcPrivateKeyFromSec1ToPkcs8(input: ByteArray): ByteArray {
    val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), input)

    checkNotNull(ecPrivateKey.parameters) { "EC Parameters are not present in the key" }

    val privateKeyInfo = PrivateKeyInfo(
        version = 0,
        privateKeyAlgorithm = EcAlgorithmIdentifier(ecPrivateKey.parameters),
        privateKey = input
    )
    return Der.encodeToByteArray(PrivateKeyInfo.serializer(), privateKeyInfo)
}
