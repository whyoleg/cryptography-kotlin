/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(CryptographyProviderApi::class)

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Digest : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<Digest>
    public fun hasher(): Hasher
}

@DelicateCryptographyApi
public object MD5 : CryptographyAlgorithmId<Digest>("MD5")

@DelicateCryptographyApi
public object SHA1 : CryptographyAlgorithmId<Digest>("SHA-1")
public object SHA224 : CryptographyAlgorithmId<Digest>("SHA-224")
public object SHA256 : CryptographyAlgorithmId<Digest>("SHA-256")
public object SHA384 : CryptographyAlgorithmId<Digest>("SHA-384")
public object SHA512 : CryptographyAlgorithmId<Digest>("SHA-512")

@Suppress("ClassName")
public object SHA3_224 : CryptographyAlgorithmId<Digest>("SHA3-224")

@Suppress("ClassName")
public object SHA3_256 : CryptographyAlgorithmId<Digest>("SHA3-256")

@Suppress("ClassName")
public object SHA3_384 : CryptographyAlgorithmId<Digest>("SHA3-384")

@Suppress("ClassName")
public object SHA3_512 : CryptographyAlgorithmId<Digest>("SHA3-512")

@DelicateCryptographyApi
public object RIPEMD160 : CryptographyAlgorithmId<Digest>("RIPEMD-160")
