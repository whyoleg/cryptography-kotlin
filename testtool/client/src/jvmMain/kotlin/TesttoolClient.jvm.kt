/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.client

internal actual fun hostOverride(): String? {
    // on android emulator `localhost` is not accessible, and we need to use this specific address
    if (System.getProperty("java.vendor")!!.contains("android", ignoreCase = true)) {
        return "10.0.2.2"
    }
    return null
}
