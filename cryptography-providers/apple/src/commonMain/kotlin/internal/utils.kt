/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*

internal val CFErrorRefVar.releaseAndGetMessage get() = value.releaseBridgeAs<NSError>()?.description

@Suppress("UNCHECKED_CAST")
internal fun <T : Any> Any?.retainBridgeAs(): T? = retainBridge()?.let { it as T }
internal fun Any?.retainBridge(): CFTypeRef? = CFBridgingRetain(this)

@Suppress("UNCHECKED_CAST")
internal fun <T : Any> CFTypeRef?.releaseBridgeAs(): T? = releaseBridge()?.let { it as T }
internal fun CFTypeRef?.releaseBridge(): Any? = CFBridgingRelease(this)

internal fun CFTypeRef?.release(): Unit = CFRelease(this)

internal inline fun <T : CFTypeRef?, R> T.use(block: (T) -> R): R {
    try {
        return block(this)
    } finally {
        releaseBridge()
    }
}

internal fun CFMutableDictionaryRef?.add(key: CFTypeRef?, value: CFTypeRef?) {
    CFDictionaryAddValue(this, key, value)
}

@Suppress("FunctionName")
@OptIn(UnsafeNumber::class)
internal inline fun CFMutableDictionary(size: Int, block: CFMutableDictionaryRef?.() -> Unit): CFMutableDictionaryRef? {
    val dict = CFDictionaryCreateMutable(null, size.convert(), null, null)
    dict.block()
    return dict
}
