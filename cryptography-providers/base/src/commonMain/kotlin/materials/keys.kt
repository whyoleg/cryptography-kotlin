/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.materials

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.unsafe.*

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
public fun wrapSubjectPublicKeyInfo(identifier: KeyAlgorithmIdentifier, key: ByteArray): ByteArray {
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
public fun wrapPrivateKeyInfo(version: Int, identifier: KeyAlgorithmIdentifier, key: ByteArray): ByteArray {
    return Der.encodeToByteArray(
        PrivateKeyInfo.serializer(),
        PrivateKeyInfo(version, identifier, key)
    )
}
