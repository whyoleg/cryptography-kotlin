/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

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
        check(it.privateKeyAlgorithm.algorithm == algorithm)
    }.privateKey

internal fun wrapPrivateKey(version: Int, identifier: KeyAlgorithmIdentifier, key: ByteArray): ByteArray = Der.encodeToByteArray(
    PrivateKeyInfo.serializer(),
    PrivateKeyInfo(version, identifier, key)
)

internal fun decodeSecKey(input: ByteArray, attributes: CFMutableDictionaryRef?): SecKeyRef = memScoped {
    val error = alloc<CFErrorRefVar>()
    input.useNSData {
        SecKeyCreateWithData(
            keyData = it.retainBridgeAs(),
            attributes = attributes,
            error = error.ptr
        )
    } ?: error("Failed to decode key: ${error.releaseAndGetMessage}")
}

// returns private key
internal fun generateSecKey(attributes: CFMutableDictionaryRef?): SecKeyRef = memScoped {
    val error = alloc<CFErrorRefVar>()
    SecKeyCreateRandomKey(
        parameters = attributes,
        error = error.ptr
    ) ?: error("Failed to generate key pair: ${error.releaseAndGetMessage}")
}

internal fun exportSecKey(key: SecKeyRef): ByteArray = memScoped {
    val error = alloc<CFErrorRefVar>()
    SecKeyCopyExternalRepresentation(
        key = key,
        error = error.ptr
    )?.releaseBridgeAs<NSData>()
        ?.toByteArray()
        ?: error("Failed to export key: ${error.releaseAndGetMessage}")
}
