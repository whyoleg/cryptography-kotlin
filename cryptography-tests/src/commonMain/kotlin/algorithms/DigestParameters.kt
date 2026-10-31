/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

// digest used as a parameter of other algorithms (HMAC, ECDSA, RSA, HKDF, etc.)
typealias SerializableDigest = @Serializable(DigestSerializer::class) CryptographyAlgorithmId<Digest>

val allDigests: List<CryptographyAlgorithmId<Digest>> = listOf(
    MD5, SHA1, SHA224, SHA256, SHA384, SHA512,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    RIPEMD160,
)

// output size in bytes
val CryptographyAlgorithmId<Digest>.digestSize: Int
    get() = when (this) {
        MD5              -> 16
        SHA1, RIPEMD160  -> 20
        SHA224, SHA3_224 -> 28
        SHA256, SHA3_256 -> 32
        SHA384, SHA3_384 -> 48
        SHA512, SHA3_512 -> 64
        else             -> error("Unknown digest: $name")
    }

// block size in bytes (f.e. for HMAC key sizes)
val CryptographyAlgorithmId<Digest>.digestBlockSize: Int
    get() = when (this) {
        MD5, SHA1, SHA224, SHA256, RIPEMD160 -> 64
        SHA384, SHA512                       -> 128
        SHA3_224                             -> 144
        SHA3_256                             -> 136
        SHA3_384                             -> 104
        SHA3_512                             -> 72
        else                                 -> error("Unknown digest: $name")
    }

internal object DigestSerializer : KSerializer<CryptographyAlgorithmId<Digest>> {
    private val digests = allDigests.associateBy { it.name }

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("dev.whyoleg.cryptography.algorithms.Digest", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CryptographyAlgorithmId<Digest>) {
        encoder.encodeString(value.name)
    }

    override fun deserialize(decoder: Decoder): CryptographyAlgorithmId<Digest> {
        return digests.getValue(decoder.decodeString())
    }
}

// digest is not supported by the provider (f.e. `MessageDigest` in JDK), shared by digest algorithms and algorithms using a digest;
// `null` if the digest is supported or not used
fun TestLimitationScope.failsIfDigestUnsupported(digest: CryptographyAlgorithmId<Digest>?): TestLimitation? = fails(
    when {
        digest == null                                                     -> null
        digest == MD5 && provider.isWebCrypto                              -> "${digest.name} is not supported"
        digest == SHA224 && (provider.isWebCrypto || provider.isCryptoKit) -> "${digest.name} is not supported"
        digest in sha3Digests && (provider.isWebCrypto || provider.isApple || provider.isCryptoKit)
                                                                     -> "SHA3 digests are not supported"
        digest in sha3Digests && provider.isJdkDefault &&
                (platform.isJdk { major < 9 } || platform.isAndroid) -> "SHA3 digests are not supported on JDK 8 and Android without BouncyCastle"
        digest == RIPEMD160 && provider.isJdkDefault                       -> "${digest.name} is supported only with BouncyCastle"
        digest == RIPEMD160 && (provider.isApple || provider.isWebCrypto || provider.isCryptoKit)
                                                                           -> "${digest.name} is not supported"
        else                                                               -> null
    } ?: return null
)

// digest based HMAC and signatures (f.e. `Mac` and `Signature` in JDK):
// SHA3 `MessageDigest` is available since JDK 9, but SHA3 based `Mac` and `Signature` only since JDK 17
fun TestLimitationScope.failsIfSignatureDigestUnsupported(digest: CryptographyAlgorithmId<Digest>?): TestLimitation? =
    failsIfDigestUnsupported(digest) ?: when {
        digest in sha3Digests && provider.isJdkDefault && platform.isJdk { major < 17 }
            -> fails("SHA3 based HMAC and signatures are supported only since JDK 17 or with BouncyCastle")
        else -> null
    }

internal val sha3Digests = setOf(SHA3_224, SHA3_256, SHA3_384, SHA3_512)
