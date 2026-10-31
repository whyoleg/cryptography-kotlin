/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testhost

import kotlinx.cinterop.*

internal actual val defaultTestStorageClient: TestStorageClient = FileSystemTestStorageClient()

@OptIn(ExperimentalForeignApi::class)
internal actual fun getenv(key: String): String? = platform.posix.getenv(key)?.toKString()
