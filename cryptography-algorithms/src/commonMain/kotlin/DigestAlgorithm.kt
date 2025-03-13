/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import kotlin.jvm.*

@JvmInline
public value class DigestAlgorithm(public val name: String) {
    public companion object {
        public val Sha1: DigestAlgorithm = DigestAlgorithm("SHA-1")
        public val Sha256: DigestAlgorithm = DigestAlgorithm("SHA-256")
        public val Sha512: DigestAlgorithm = DigestAlgorithm("SHA-512")
    }
}
