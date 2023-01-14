package dev.whyoleg.cryptography.test.suite

internal actual val currentPlatform: String by lazy {
    "JVM(${System.getProperty("java.version")})"
}
