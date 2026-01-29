/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.*

fun AlgorithmTestScope<*>.supportsFunctions() = supports {
    when {
        provider.isWebCrypto -> "Incremental functions"
        else                 -> null
    }
}

fun AlgorithmTestScope<ECDSA>.supportsSignatureDigest(digest: CryptographyAlgorithmId<Digest>?): Boolean = when (digest) {
    null -> supports {
        when {
            provider.isJdkDefault || provider.isWebCrypto || provider.isCryptoKit -> "ECDSA without digest"
            else                                                                  -> null
        }
    }
    else -> supportsDigest(digest)
}

fun AlgorithmTestScope<*>.supportsDigest(digest: CryptographyAlgorithmId<Digest>): Boolean = supports {
    val sha3Algorithms = setOf(SHA3_224, SHA3_256, SHA3_384, SHA3_512)

    when {
        (digest == SHA224 || digest in sha3Algorithms) &&
                (provider.isWebCrypto || provider.isCryptoKit) -> digest.name

        digest in sha3Algorithms &&
                provider.isApple                               -> digest.name

        digest in sha3Algorithms &&
                provider.isJdkDefault &&
                (platform.isJdk { major < 17 } || platform.isAndroid) -> "${digest.name} signatures on old JDK"

        digest == RIPEMD160 && (provider.isJdkDefault || provider.isApple || provider.isWebCrypto || provider.isCryptoKit)
                                                               -> digest.name

        else                                                   -> null
    }
}

fun AlgorithmTestScope<*>.supportsKeyFormat(format: KeyFormat): Boolean = supports {
    when {
        // only WebCrypto supports JWK for now
        format.name == "JWK" && !provider.isWebCrypto
             -> "JWK key format"
        format == EC.PublicKey.Format.RAW.Compressed && provider.isApple
             -> "compressed key format"
        else -> null
    }
}

// WebCrypto doesn't support encryption without padding
fun AlgorithmTestScope<AES.CBC>.supportsPadding(padding: Boolean): Boolean = supports {
    when {
        provider.isWebCrypto && !padding -> "no padding"
        else                             -> null
    }
}

// CryptoKit supports only the default tag size
fun AlgorithmTestScope<AES.GCM>.supportsTagSize(tagSize: BinarySize): Boolean = supports {
    when {
        provider.isCryptoKit && tagSize != 16.bytes -> "non-default tag size"
        else                                        -> null
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

fun AlgorithmTestScope<out EC<*, *, *>>.supportsCurve(curve: EC.Curve): Boolean = supports {
    when {
        // JDK default, WebCrypto and Apple don't support secp256k1 or brainpool
        curve in listOf(EC.Curve.secp256k1, EC.Curve.brainpoolP256r1, EC.Curve.brainpoolP384r1, EC.Curve.brainpoolP512r1) && (
                provider.isJdkDefault || provider.isWebCrypto || provider.isApple || provider.isCryptoKit
                ) -> "ECDSA ${curve.name}"

        else      -> null
    }
}

fun AlgorithmTestScope<out EC<*, *, *>>.supportsPublicKeyAccess(error: Throwable): Boolean = supports {
    when {
        provider.isJdkDefault &&
                error.message == "Getting public key from private key for EC is not supported in JDK without BouncyCastle APIs"
             -> error.message!!
        else -> null
    }
}

fun AlgorithmTestScope<X25519>.supportsX25519PublicKeyDerivation(error: Throwable): Boolean = supports {
    when {
        provider.isJdkDefault &&
                error.message?.contains("Cannot derive public key from X25519 private key") == true
             -> error.message!!
        else -> null
    }
}

fun AlgorithmTestScope<out EC<*, *, *>>.supportsPrivateKeyDecoding(
    format: EC.PrivateKey.Format,
    key: ByteString,
    otherContext: TestContext,
): Boolean = supports {
    fun hasPublicKey(): Boolean {
        fun validateEcPrivateKey(bytes: ByteString) =
            Der.decodeFromByteArray(EcPrivateKey.serializer(), bytes.toByteArray()).publicKey != null

        fun decodePki(bytes: ByteString): ByteString =
            ByteString(Der.decodeFromByteArray(PrivateKeyInfo.serializer(), bytes.toByteArray()).privateKey)

        return validateEcPrivateKey(
            when (format) {
                EC.PrivateKey.Format.JWK      -> return true
                EC.PrivateKey.Format.RAW      -> return false
                EC.PrivateKey.Format.DER      -> decodePki(key)
                EC.PrivateKey.Format.DER.SEC1 -> key
                EC.PrivateKey.Format.PEM      -> decodePki(PemDocument.decode(key).content)
                EC.PrivateKey.Format.PEM.SEC1 -> PemDocument.decode(key).content
            }
        )
    }

    when {
        provider.isApple
                && format == EC.PrivateKey.Format.RAW -> "private key '$format' format"
        provider.isApple
                && !hasPublicKey()                    -> "private key '$format' format without 'publicKey' from ${otherContext.provider}"
        else                                          -> null
    }
}

fun ProviderTestScope.supports(algorithmId: CryptographyAlgorithmId<*>): Boolean = validate {
    when (algorithmId) {
        AES.CMAC if provider.isJdkDefault                                          -> "Default JDK provider doesn't support AES-CMAC, only supported with BouncyCastle"
        RSA.PSS if provider.isJdkDefault && platform.isAndroid                     -> "JDK provider on Android doesn't support RSASSA-PSS"
        ChaCha20Poly1305 if provider.isJdkDefault && platform.isJdk { major < 11 } -> "Default JDK provider supports ChaCha20-Poly1305 from JDK 11"
        ED25519 if provider.isJdkDefault && platform.isJdk { major < 15 }          -> "Default JDK provider supports ED25519 from JDK 15"
        ED25519 if provider.isJdkDefault && platform.isAndroid                     -> "JDK provider on Android doesn't support ED25519"
        ED25519 if provider.isWebCrypto                                            -> "WebCrypto doesn't support ED25519"
        ED25519 if provider.isApple                                                -> "Apple provider doesn't support ED25519 yet"
        X25519 if provider.isJdkDefault && platform.isJdk { major < 11 }           -> "Default JDK provider supports X25519 from JDK 11"
        X25519 if provider.isJdkDefault && platform.isAndroid                      -> "JDK provider on Android doesn't support X25519"
        X25519 if provider.isWebCrypto                                             -> "WebCrypto doesn't support X25519"
        X25519 if provider.isApple                                                 -> "Apple provider doesn't support X25519 yet"
        ChaCha20 if provider.isJdkDefault && platform.isJdk { major < 11 }         -> "Default JDK provider supports ChaCha20 from JDK 11"
        ChaCha20 if provider.isJdkDefault && platform.isAndroid                    -> "JDK provider on Android doesn't support ChaCha20"
        ChaCha20 if provider.isWebCrypto                                           -> "WebCrypto doesn't support ChaCha20"
        ChaCha20 if provider.isApple                                               -> "Apple provider doesn't support ChaCha20 yet"
        Poly1305 if provider.isWebCrypto                                           -> "WebCrypto doesn't support Poly1305"
        Poly1305 if provider.isApple                                               -> "Apple provider doesn't support Poly1305 yet"
        else                                                                       -> null
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
