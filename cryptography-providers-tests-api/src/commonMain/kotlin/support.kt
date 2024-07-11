/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*

fun AlgorithmTestScope<*>.supportsDigest(digest: CryptographyAlgorithmId<Digest>): Boolean = supports {
    val sha3Algorithms = setOf(SHA3_224, SHA3_256, SHA3_384, SHA3_512)
    when {
        (digest == SHA224 || digest in sha3Algorithms) &&
                provider.isWebCrypto                                  -> digest.name
        digest in sha3Algorithms &&
                provider.isApple                                      -> digest.name
        digest in sha3Algorithms &&
                provider.isJdkDefault &&
                (platform.isJdk { major < 17 } || platform.isAndroid) -> "${digest.name} signatures on old JDK"
        else                                                          -> null
    }
}

fun AlgorithmTestScope<*>.supportsKeyFormat(format: KeyFormat): Boolean = supports {
    when {
        // only WebCrypto supports JWK for now
        format.name == "JWK" &&
                !provider.isWebCrypto -> "JWK key format"
        else                          -> null
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

fun AlgorithmTestScope<RSA.PSS>.supportsSaltSize(saltSize: Int?): Boolean = supports {
    when {
        provider.isApple && saltSize != null -> "custom saltSize"
        else                                 -> null
    }
}

fun AlgorithmTestScope<RSA.OAEP>.supportsAssociatedData(associatedDataSize: Int?): Boolean = supports {
    when {
        provider.isApple && associatedDataSize != null -> "associatedData"
        else                                           -> null
    }
}

fun AlgorithmTestScope<RSA.PKCS1>.supportsEncryption(): Boolean = supports {
    when {
        provider.isWebCrypto -> "PKCS1 encryption"
        else                 -> null
    }
}

fun AlgorithmTestScope<ECDSA>.supportsCurve(curve: EC.Curve): Boolean = supports {
    when {
        // JDK default, WebCrypto and Apple doesn't support secp256k1
        curve.name == "secp256k1" && (
                provider.isJdkDefault || provider.isWebCrypto || provider.isApple
                ) -> "ECDSA ${curve.name}"
        else      -> null
    }
}

fun ProviderTestScope.supports(algorithmId: CryptographyAlgorithmId<*>): Boolean = validate {
    when {
        algorithmId == RSA.PSS &&
                provider.isJdkDefault &&
                platform.isAndroid                    -> "JDK provider on Android doesn't support RSASSA-PSS"
        provider.isJdkDefault &&
                platform.isAndroid { apiLevel == 21 } -> "JDK provider on Android API 21 is super unstable"
        algorithmId == ECDSA &&
                provider.isJdkDefault &&
                platform.isAndroid { apiLevel == 27 } -> "Key encoding of ECDSA DER key on Android API 27 is flaky - ignore for now"
        else                                          -> null
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
