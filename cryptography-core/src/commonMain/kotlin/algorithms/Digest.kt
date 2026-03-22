/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(CryptographyProviderApi::class)

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

/**
 * Cryptographic hash (message digest) algorithm.
 *
 * Digest algorithms compute a fixed-size hash value from arbitrary input data.
 * Concrete algorithms are available as top-level [CryptographyAlgorithmId] objects
 * (e.g., [SHA256], [SHA512], [SHA3_256]).
 *
 * ```
 * val digest = provider.get(SHA256).hasher().hash(data)
 * ```
 *
 * For keyed hash-based message authentication, see [HMAC].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Digest : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<Digest>

    /**
     * Returns a [Hasher] that computes digests using this algorithm.
     */
    public fun hasher(): Hasher
}

/**
 * MD5 message digest algorithm defined in [RFC 1321](https://datatracker.ietf.org/doc/html/rfc1321).
 */
@DelicateCryptographyApi
public object MD5 : CryptographyAlgorithmId<Digest>("MD5")

/**
 * SHA-1 message digest algorithm defined in [RFC 3174](https://datatracker.ietf.org/doc/html/rfc3174).
 */
@DelicateCryptographyApi
public object SHA1 : CryptographyAlgorithmId<Digest>("SHA-1")

/**
 * SHA-224 message digest algorithm from the SHA-2 family defined in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
 */
public object SHA224 : CryptographyAlgorithmId<Digest>("SHA-224")

/**
 * SHA-256 message digest algorithm from the SHA-2 family defined in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
 */
public object SHA256 : CryptographyAlgorithmId<Digest>("SHA-256")

/**
 * SHA-384 message digest algorithm from the SHA-2 family defined in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
 */
public object SHA384 : CryptographyAlgorithmId<Digest>("SHA-384")

/**
 * SHA-512 message digest algorithm from the SHA-2 family defined in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
 */
public object SHA512 : CryptographyAlgorithmId<Digest>("SHA-512")

/**
 * SHA3-224 message digest algorithm from the SHA-3 family defined in [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
 * Produces a 224-bit hash value.
 */
@Suppress("ClassName")
public object SHA3_224 : CryptographyAlgorithmId<Digest>("SHA3-224")

/**
 * SHA3-256 message digest algorithm from the SHA-3 family defined in [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
 */
@Suppress("ClassName")
public object SHA3_256 : CryptographyAlgorithmId<Digest>("SHA3-256")

/**
 * SHA3-384 message digest algorithm from the SHA-3 family defined in [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
 */
@Suppress("ClassName")
public object SHA3_384 : CryptographyAlgorithmId<Digest>("SHA3-384")

/**
 * SHA3-512 message digest algorithm from the SHA-3 family defined in [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
 */
@Suppress("ClassName")
public object SHA3_512 : CryptographyAlgorithmId<Digest>("SHA3-512")

/**
 * RIPEMD-160 message digest algorithm used in cryptocurrencies.
 */
@DelicateCryptographyApi
public object RIPEMD160 : CryptographyAlgorithmId<Digest>("RIPEMD-160")
