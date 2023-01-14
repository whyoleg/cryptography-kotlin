package dev.whyoleg.cryptography.test.step.api

internal actual val currentPlatform: String by lazy {
    "${Platform.osFamily}-${Platform.cpuArchitecture}"
}
