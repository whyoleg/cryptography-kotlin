package dev.whyoleg.cryptography.test.step.api

import dev.whyoleg.cryptography.provider.*

internal expect val supportedProviders: List<CryptographyProvider>

val CryptographyProvider.isWebCrypto: Boolean
    get() = name == "WebCrypto"

val CryptographyProvider.isJdk: Boolean
    get() = name == "JDK"

val CryptographyProvider.isApple: Boolean
    get() = name == "Apple"

val CryptographyProvider.supportsJwk: Boolean
    get() = isWebCrypto
