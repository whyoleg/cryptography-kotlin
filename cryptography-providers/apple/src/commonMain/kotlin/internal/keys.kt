/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.providers.base.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

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
