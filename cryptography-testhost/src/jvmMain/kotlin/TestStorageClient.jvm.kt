/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

internal actual val defaultTestStorageClient: TestStorageClient = when {
    isAndroid -> HttpTestStorageClient()
    else      -> FileSystemTestStorageClient()
}

internal actual fun getenv(key: String): String? = System.getenv(key)

// on android emulator `localhost` is not accessible, and we need to use this specific address
internal actual fun hostOverride(): String? = when {
    isAndroid -> "10.0.2.2"
    else      -> null
}
