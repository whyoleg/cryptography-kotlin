package dev.whyoleg.cryptography.test.utils

expect val currentPlatform: String

expect val currentPlatformJvmVersion: Int?

val currentPlatformIsBrowser: Boolean get() = currentPlatform.startsWith("JS(Browser)")
