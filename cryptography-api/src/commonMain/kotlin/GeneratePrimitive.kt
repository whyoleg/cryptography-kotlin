/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

public interface GeneratePrimitive<P, K> : CryptographyPrimitive {
    public fun generate(parameters: P): K
}
