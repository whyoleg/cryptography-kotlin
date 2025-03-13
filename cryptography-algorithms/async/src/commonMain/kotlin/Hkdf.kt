/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.async

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.primitives.async.*

public interface Hkdf : SecretDerivationPrimitive<HkdfDeriveParameters> {
    public companion object Tag : CryptographyProvider.Tag<Hkdf, HkdfParameters>
}
