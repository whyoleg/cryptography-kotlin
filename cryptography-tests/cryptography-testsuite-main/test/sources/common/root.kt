package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.provider.*

val CryptographyProvider.isWebCrypto: Boolean
    get() = name == "WebCrypto"

val CryptographyProvider.isJdk: Boolean
    get() = name == "JDK"

val CryptographyProvider.isApple: Boolean
    get() = name == "Apple"


internal expect val supportedProviders: List<CryptographyProvider>

suspend fun <KF : KeyFormat> EncodableKey<KF>.encodeToIf(supported: Boolean, format: KF): ByteArray? {
    return if (supported) encodeTo(format) else null
}

suspend fun <KF : KeyFormat, K : Key> KeyDecoder<KF, K>.decodeFromIf(supported: Boolean, format: KF, encoded: ByteArray): K? {
    return if (supported) decodeFrom(format, encoded) else null
}
