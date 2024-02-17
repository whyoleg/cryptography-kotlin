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
        format.name == "JWK" && !provider.isWebCrypto                      -> "JWK"
        // will be supported if ASN.1 serialization is ready - TODO JDK support, may be it's available
        format.name in setOf("PEM/PKCS#1", "DER/PKCS#1") && provider.isJdk -> "$format not yet available in $provider"
        else                                                               -> null
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

fun AlgorithmTestScope<ECDSA>.supportsCurve(curve: EC.Curve): Boolean = supports {
    // default curves supported everywhere now
    if (curve.name != "secp256k1") return@supports null

    when {
        // JDK default and WebCrypto doesn't support it
        provider.isJdkDefault || provider.isWebCrypto -> "ECDSA $curve"
        else                                          -> null
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

        // JDK.Default support the DER signature format only starting from java 9 and there is no support at all on android
        provider.isJdkDefault &&
                (platform.isJdk { major <= 8 } || platform.isAndroid) &&
                format == ECDSA.SignatureFormat.RAW -> "$format signature format on JDK < 9 or Android"

        else                                        -> null
    }
}

// Private key DER encoding of EC keys could be different per providers
//  while it can be both decoded and encoded successfully, their encoding will be not equal
fun AlgorithmTestScope<ECDSA>.supportsPrivateKeyDerComparisonWith(
    other: TestContext,
): Boolean = validate {
    fun TestContext.isWebCryptoBrowser(): Boolean = provider.isWebCrypto && platform.isBrowser
    when {
        context.isWebCryptoBrowser() != other.isWebCryptoBrowser()       -> {
            "WebCrypto on browser always encodes additional parameters"
        }
        context.provider.isBouncyCastle != other.provider.isBouncyCastle -> {
            "BouncyCastle always encodes additional parameters"
        }
        else                                                             -> null
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
