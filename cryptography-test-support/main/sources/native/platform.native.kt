package dev.whyoleg.cryptography.test.support

actual val currentPlatform: String by lazy {
    "Native [os=${Platform.osFamily}, arch=${Platform.cpuArchitecture}, debug=${Platform.isDebugBinary}]"
}
