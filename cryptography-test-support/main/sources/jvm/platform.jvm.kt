package dev.whyoleg.cryptography.test.support

actual val currentPlatform: String by lazy {
    "JVM(v=${System.getProperty("java.version")}, os=${System.getProperty("os.name")}, arch=${System.getProperty("os.arch")})"
}
