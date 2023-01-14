package dev.whyoleg.cryptography.test.suite

internal actual val currentPlatform: String by lazy {
    "${Platform.osFamily}-${Platform.cpuArchitecture}"
}
