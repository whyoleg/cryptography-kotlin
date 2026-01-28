/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.internal

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*

// Extract public key bytes from PKCS#8 encoding (RFC 8410 OneAsymmetricKey)
internal fun getPublicKeyFromPrivateKeyPkcs8(algorithm: ObjectIdentifier, key: ByteArray): ByteArray? {
    val privateKeyInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), key)
    check(privateKeyInfo.privateKeyAlgorithm.algorithm == algorithm) {
        "Expected algorithm '${algorithm.value}', received: '${privateKeyInfo.privateKeyAlgorithm.algorithm}'"
    }
    return privateKeyInfo.publicKey?.byteArray
}

internal fun getEcPublicKeyFromPrivateKeyPkcs8(input: ByteArray): ByteArray? {
    val privateKeyInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)
    val privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm
    check(privateKeyAlgorithm is EcAlgorithmIdentifier) {
        "Expected algorithm '${ObjectIdentifier.EC}', received: '${privateKeyAlgorithm.algorithm}'"
    }
    val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), privateKeyInfo.privateKey)
    return ecPrivateKey.publicKey?.byteArray
}
