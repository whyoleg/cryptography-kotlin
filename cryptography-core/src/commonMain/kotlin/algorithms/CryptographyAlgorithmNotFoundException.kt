/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmId<*>,
) : CryptographyException("Algorithm not found: $algorithm")
