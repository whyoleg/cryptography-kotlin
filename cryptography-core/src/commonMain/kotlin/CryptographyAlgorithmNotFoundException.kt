/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@Suppress("DEPRECATION_ERROR")
@Deprecated(
    "IllegalStateException is throw instead",
    level = DeprecationLevel.ERROR
)
public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmId<*>,
) : CryptographyException("Algorithm not found: $algorithm")
