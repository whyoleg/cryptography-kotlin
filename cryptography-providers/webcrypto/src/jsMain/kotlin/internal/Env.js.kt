/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

internal actual fun detectEngine(): Engine {
    // Node.js detection
    val isNode = js("typeof process !== 'undefined' && process.versions && process.versions.node") as Boolean? ?: false
    if (isNode) return Engine.Node

    // Browser detection via userAgent
    val ua = try {
        js("navigator.userAgent") as String
    } catch (_: dynamic) {
        ""
    }

    return when {
        ua.contains("Firefox", ignoreCase = true) -> Engine.Firefox
        // Chromium derivatives first
        ua.contains("Edg", ignoreCase = true) || ua.contains("OPR", ignoreCase = true) || ua.contains("Chrome", ignoreCase = true) || ua.contains("Chromium", ignoreCase = true) -> Engine.Chromium
        // Safari (exclude Chrome/Chromium matches above)
        ua.contains("Safari", ignoreCase = true) && ua.contains("AppleWebKit", ignoreCase = true) -> Engine.Safari
        else -> Engine.Unknown
    }
}

