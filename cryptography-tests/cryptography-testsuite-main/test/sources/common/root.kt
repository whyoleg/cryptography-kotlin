package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.provider.*

val CryptographyProvider.isWebCrypto: Boolean
    get() = name == "WebCrypto"

val CryptographyProvider.isJdk: Boolean
    get() = name == "JDK"

val CryptographyProvider.isApple: Boolean
    get() = name == "Apple"


internal expect val supportedProviders: List<CryptographyProvider>
