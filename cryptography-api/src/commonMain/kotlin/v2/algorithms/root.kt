/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.v2.algorithms

public interface DigestAlgorithm {
    public val name: String

    public companion object {
        public val Sha1: DigestAlgorithm = object : DigestAlgorithm {
            override val name: String = "SHA-1"
        }
    }
}

public class DigestParameters(
    public val algorithm: DigestAlgorithm,
)
