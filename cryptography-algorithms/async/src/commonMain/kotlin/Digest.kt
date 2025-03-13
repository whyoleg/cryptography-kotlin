/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.async

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.primitives.async.*

public interface Digest : HashPrimitive<Unit> {
    public val outputSize: BinarySize

    public companion object Tag : CryptographyProvider.Tag<Digest, DigestParameters>
}

public interface ShakeDigest : HashPrimitive<ShakeHashParameters> {
    public companion object Tag : CryptographyProvider.Tag<ShakeDigest, ShakeParameters>
}
