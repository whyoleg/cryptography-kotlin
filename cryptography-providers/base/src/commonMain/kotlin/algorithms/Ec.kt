/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*

@CryptographyProviderApi
public fun convertEcPrivateKeyFromPkcs8ToSec1(input: ByteArray): ByteArray {
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

@CryptographyProviderApi
public fun convertEcPrivateKeyFromSec1ToPkcs8(input: ByteArray): ByteArray {
    val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), input)

    checkNotNull(ecPrivateKey.parameters) { "EC Parameters are not present in the key" }

    val privateKeyInfo = PrivateKeyInfo(
        version = 0,
        privateKeyAlgorithm = EcKeyAlgorithmIdentifier(ecPrivateKey.parameters),
        privateKey = input
    )
    return Der.encodeToByteArray(PrivateKeyInfo.serializer(), privateKeyInfo)
}
