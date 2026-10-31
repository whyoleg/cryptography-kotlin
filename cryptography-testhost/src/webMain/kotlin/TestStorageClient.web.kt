/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

internal actual val defaultTestStorageClient: TestStorageClient = HttpTestStorageClient()

internal actual fun hostOverride(): String? = null
