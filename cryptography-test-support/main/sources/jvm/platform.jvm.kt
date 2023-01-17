package dev.whyoleg.cryptography.test.support

actual val currentPlatform: String by lazy {
    "JVM(${System.getProperty("java.version")})"
}
