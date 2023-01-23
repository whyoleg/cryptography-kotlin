package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.provider.*

expect val availableProviders: List<CryptographyProvider>

val CryptographyProvider.isWebCrypto: Boolean
    get() = name == "WebCrypto"

val CryptographyProvider.isJdk: Boolean
    get() = name == "JDK"

val CryptographyProvider.isApple: Boolean
    get() = name == "Apple"

val CryptographyProvider.supportsJwk: Boolean
    get() = isWebCrypto

// Private key DER encoding is different per providers (e.g. PKCS#8 vs. SEC1)
// it's more of a hack now (to test at least jdk vs nodejs) then a real and correct check
val CryptographyProvider.supportsEcPrivateKeyDer: Boolean
    get() = !(isWebCrypto && currentPlatformIsBrowser)
