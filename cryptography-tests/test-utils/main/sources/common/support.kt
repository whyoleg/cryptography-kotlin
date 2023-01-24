package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.*

fun ProviderTestContext.supports(feature: String, condition: Boolean): Boolean {
    if (condition) return true

    logger.log { "SKIP: `$feature` is not supported by ${provider.name}" }
    return false
}

// only WebCrypto supports JWK for now
fun ProviderTestContext.supportsJwk(): Boolean = supports(
    feature = "JWK",
    condition = provider.isWebCrypto
)

// WebCrypto supports only encryption with padding
fun AlgorithmTestContext<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports(
    feature = when {
        padding -> "PKCS7Padding"
        else    -> "No padding"
    },
    condition = if (provider.isWebCrypto) padding else true
)

// WebCrypto BROWSER(or only chromium) doesn't support 192bits
// https://bugs.chromium.org/p/chromium/issues/detail?id=533699
fun AlgorithmTestContext<out AES<*>>.supportsKeySize(keySizeBits: Int): Boolean = supports(
    feature = "${keySizeBits.bits} key",
    condition = if (provider.isWebCrypto && currentPlatformIsBrowser) keySizeBits != 192 else true
)

fun AlgorithmTestContext<ECDSA>.supportsSignatureFormat(format: ECDSA.SignatureFormat): Boolean = supports(
    feature = "$format signature format",
    condition = when {
        //WebCrypto supports only RAW signature format
        provider.isWebCrypto                               -> format == ECDSA.SignatureFormat.RAW
        //JDK supports RAW signature format starting from java 9
        provider.isJdk && currentPlatformJvmVersion!! <= 8 -> format == ECDSA.SignatureFormat.DER
        else                                               -> true
    }
)

// Private key DER encoding is different per providers (e.g. PKCS#8 vs. SEC1)
// it's more of a hack now (to test at least jdk vs nodejs) then a real and correct check
fun AlgorithmTestContext<ECDSA>.supportsPrivateKeyDerFormat(): Boolean = supports(
    feature = "EC DER private key encoding",
    condition = when {
        provider.isWebCrypto -> !currentPlatformIsBrowser
        else                 -> true
    }
)
