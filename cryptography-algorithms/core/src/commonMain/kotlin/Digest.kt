/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.core

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.primitives.core.*

public interface Digest : HashPrimitive {
    public companion object Tag : CryptographyProvider.Tag<Digest, DigestParameters>
}

public interface ShakeDigest : ExtendableHashFunction {
    public companion object Tag : CryptographyProvider.Tag<ShakeDigest, ShakeParameters>
}
