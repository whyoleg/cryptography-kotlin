/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*

// only WebCrypto supports JWK for now
fun AlgorithmTestScope<*>.supportsKeyFormat(format: KeyFormat): Boolean = supports {
    when {
        format.name == "JWK" && !provider.isWebCrypto -> "JWK"
        else                                          -> null
    }
}

// WebCrypto doesn't support encryption without padding
fun AlgorithmTestScope<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports {
    when {
        provider.isWebCrypto && !padding -> "no padding"
        else                             -> null
    }
}

// WebCrypto BROWSER(or only chromium) doesn't support 192bits
// https://bugs.chromium.org/p/chromium/issues/detail?id=533699
fun AlgorithmTestScope<out AES<*>>.supportsKeySize(keySizeBits: Int): Boolean = supports {
    when {
        provider.isWebCrypto && platform.isBrowser && keySizeBits == 192 -> "192 bits key"
        else                                                             -> null
    }
}

fun AlgorithmTestScope<ECDSA>.supportsSignatureFormat(format: ECDSA.SignatureFormat): Boolean = supports {
    when {
        // WebCrypto doesn't support the DER signature format
        provider.isWebCrypto &&
                format == ECDSA.SignatureFormat.DER -> "$format signature format"

        // BouncyCastle doesn't support the RAW signature format
        provider.isBouncyCastle &&
                format == ECDSA.SignatureFormat.RAW -> "$format signature format"

        // JDK.Default support the DER signature format only starting from java 9
        provider.isJdkDefault && platform.isJdk { major <= 8 } &&
                format == ECDSA.SignatureFormat.RAW -> "$format signature format on JDK < 9"

        else                                        -> null
    }
}

// Private key DER encoding of EC keys could be different per providers
//  while it can be both decoded and encoded successfully, their encoding will be not equal
fun AlgorithmTestScope<ECDSA>.supportsPrivateKeyDerComparisonWith(
    other: TestContext,
): Boolean = validate {
    when {
        context.provider.isWebCrypto && context.platform.isBrowser && context != other -> {
            "WebCrypto on browser always encodes additional parameters"
        }
        context.provider.isBouncyCastle && !other.provider.isBouncyCastle              -> {
            "BouncyCastle always encodes additional parameters"
        }
        else                                                                           -> null
    }
}

private fun ProviderTestScope.supports(condition: TestContext.() -> String?): Boolean {
    return validate { condition()?.let { "'$it' is not supported" } }
}

private fun ProviderTestScope.validate(condition: TestContext.() -> String?): Boolean {
    val reason = condition(context) ?: return true
    logger.print("SKIP: $reason")
    return false
}
