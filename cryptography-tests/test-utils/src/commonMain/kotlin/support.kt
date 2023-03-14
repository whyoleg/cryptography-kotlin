/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*

fun ProviderTestContext.supports(feature: String, condition: Boolean): Boolean {
    if (condition) return true

    logger.log { "SKIP: `$feature` is not supported by ${provider.name} provider" }
    return false
}

// only WebCrypto supports JWK for now
fun AlgorithmTestContext<*>.supportsKeyFormat(format: KeyFormat): Boolean = supports(
    feature = "${format.name} Key format",
    condition = when (format.name) {
        "JWK" -> provider.isWebCrypto
        else  -> true
    }
)

// WebCrypto supports only encryption with padding
fun AlgorithmTestContext<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports(
    feature = when {
        padding -> "PKCS7Padding"
        else    -> "No padding"
    },
    condition = when {
        provider.isWebCrypto -> padding
        else                 -> true
    }
)

// WebCrypto BROWSER(or only chromium) doesn't support 192bits
// https://bugs.chromium.org/p/chromium/issues/detail?id=533699
fun AlgorithmTestContext<out AES<*>>.supportsKeySize(keySizeBits: Int): Boolean = supports(
    feature = "${keySizeBits.bits} key",
    condition = when {
        provider.isWebCrypto && currentPlatformIsBrowser -> keySizeBits != 192
        else                                             -> true
    }
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

// Private key DER encoding of EC keys is different on browser comparing to all other implementations
//  while it can be both decoded and encoded successfully, they will be not equal
//  TBD what to do here
fun AlgorithmTestContext<ECDSA>.supportsPrivateKeyDerComparison(): Boolean = supports(
    feature = "EC DER/PEM private key encoding",
    condition = when {
        provider.isWebCrypto && currentPlatformIsBrowser -> false
        else                                             -> true
    }
)
