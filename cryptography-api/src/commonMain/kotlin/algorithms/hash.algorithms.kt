/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import dev.whyoleg.cryptography.api.*
import dev.whyoleg.cryptography.api.async.*

public interface SimpleDigest : HashPrimitive<Unit> {
    public val outputSize: Int
}

public interface AsyncSimpleDigest : AsyncHashPrimitive<Unit> {
    public val outputSize: Int
}

public object Sha1 : CryptographyProvider.Tag<SimpleDigest>
public object AsyncSha1 : CryptographyProvider.Tag<AsyncSimpleDigest>
