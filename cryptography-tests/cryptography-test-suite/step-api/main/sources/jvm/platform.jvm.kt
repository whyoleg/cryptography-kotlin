package dev.whyoleg.cryptography.test.step.api

internal actual val currentPlatform: String by lazy {
    "JVM(${System.getProperty("java.version")})"
}
