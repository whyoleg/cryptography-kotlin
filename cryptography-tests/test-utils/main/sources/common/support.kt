package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.*

fun ProviderTestContext.supports(feature: String, condition: Boolean): Boolean {
    if (condition) return true

    logger.log { "SKIP: `$feature` is not supported by ${provider.name}" }
    return false
}

// WebCrypto supports only encryption with padding
fun AlgorithmTestContext<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports(
    feature = when {
        padding -> "PKCS7Padding"
        else    -> "No padding"
    },
    condition = if (provider.isWebCrypto) padding else true
)

// WebCrypto BROWSER doesn't support 192bits
fun AlgorithmTestContext<out AES<*>>.supportsKeySize(keySizeBits: Int): Boolean = supports(
    feature = "${keySizeBits.bits} key",
    condition = if (provider.isWebCrypto) keySizeBits != 192 else true
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
