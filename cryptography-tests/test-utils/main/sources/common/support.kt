package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.algorithms.symmetric.*

fun ProviderTestContext.supports(condition: Boolean, feature: String): Boolean {
    if (condition) return true

    logger.log("[TEST] SKIP: $feature is not supported by ${provider.name}")
    return false
}

// WebCrypto supports only encryption with padding
fun AlgorithmTestContext<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports(
    condition = if (provider.isWebCrypto) padding else true,
    feature = "NoPadding"
)

// WebCrypto BROWSER doesn't support 192bits - TODO: WHY???
fun AlgorithmTestContext<AES.CBC>.supportsKeySize(keySizeBits: Int): Boolean = supports(
    condition = if (provider.isWebCrypto) keySizeBits != 192 else true,
    feature = "192bit key"
)
