/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(CryptographyProviderApi::class)

package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Digest : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<Digest>
    public fun hasher(): Hasher
}

@InsecureAlgorithm
public object MD5 : CryptographyAlgorithmId<Digest>("MD5")

@InsecureAlgorithm
public object SHA1 : CryptographyAlgorithmId<Digest>("SHA-1")
public object SHA256 : CryptographyAlgorithmId<Digest>("SHA-256")
public object SHA384 : CryptographyAlgorithmId<Digest>("SHA-384")
public object SHA512 : CryptographyAlgorithmId<Digest>("SHA-512")
