package dev.whyoleg.cryptography.test.support

actual val currentPlatform: String by lazy {
    "${Platform.osFamily}-${Platform.cpuArchitecture}"
}
