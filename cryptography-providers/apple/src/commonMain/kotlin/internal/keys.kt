/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.providers.base.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal fun decodeSecKey(input: ByteArray, attributes: CFMutableDictionaryRef?): SecKey = memScoped {
    val error = alloc<CFErrorRefVar>()
    input.useNSData {
        SecKeyCreateWithData(
            keyData = it.retainBridgeAs(),
            attributes = attributes,
            error = error.ptr
        )
    }?.let(::SecKey) ?: error("Failed to decode key: ${error.releaseAndGetMessage}")
}

// returns private key
internal fun generateSecKey(attributes: CFMutableDictionaryRef?): SecKey = memScoped {
    val error = alloc<CFErrorRefVar>()
    SecKeyCreateRandomKey(
        parameters = attributes,
        error = error.ptr
    )?.let(::SecKey) ?: error("Failed to generate key pair: ${error.releaseAndGetMessage}")
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

// keys own their `SecKeyRef`, operations created from keys share the same resource
internal typealias SecKey = NativeResource<SecKeyRef>

private fun SecKey(key: SecKeyRef): SecKey = NativeResource(key, SecKeyRef::release)

internal fun SecKeyRef.copyPublicKey(): SecKey =
    SecKey(checkNotNull(SecKeyCopyPublicKey(this)) { "Failed to get public key" })
