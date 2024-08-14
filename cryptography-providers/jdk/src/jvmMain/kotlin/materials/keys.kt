/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal fun unwrapPem(label: PemLabel, key: ByteArray): ByteArray =
    Pem.decode(key).ensurePemLabel(label).bytes

internal fun wrapPem(label: PemLabel, key: ByteArray): ByteArray = Pem.encodeToByteArray(PemContent(label, key))

internal fun unwrapPublicKey(algorithm: ObjectIdentifier, key: ByteArray): ByteArray =
    Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), key).also {
        check(it.algorithm.algorithm == algorithm) { "Expected algorithm '${algorithm.value}', received: '${it.algorithm.algorithm}'" }
    }.subjectPublicKey.byteArray

internal fun wrapPublicKey(identifier: KeyAlgorithmIdentifier, key: ByteArray): ByteArray = Der.encodeToByteArray(
    SubjectPublicKeyInfo.serializer(),
    SubjectPublicKeyInfo(identifier, BitArray(0, key))
)

internal fun unwrapPrivateKey(algorithm: ObjectIdentifier, key: ByteArray): ByteArray =
    Der.decodeFromByteArray(PrivateKeyInfo.serializer(), key).also {
        check(it.privateKeyAlgorithm.algorithm == algorithm) { "Expected algorithm '${algorithm.value}', received: '${it.privateKeyAlgorithm.algorithm}'" }
    }.privateKey

internal fun wrapPrivateKey(version: Int, identifier: KeyAlgorithmIdentifier, key: ByteArray): ByteArray = Der.encodeToByteArray(
    PrivateKeyInfo.serializer(),
    PrivateKeyInfo(version, identifier, key)
)
