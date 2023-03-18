/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test

expect val currentPlatform: String

expect val currentPlatformJvmVersion: Int?

val currentPlatformIsBrowser: Boolean get() = currentPlatform.startsWith("JS(Browser)")
