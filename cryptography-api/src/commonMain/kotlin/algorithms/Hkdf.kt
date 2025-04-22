/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import dev.whyoleg.cryptography.api.*
import kotlinx.io.bytestring.*

public interface Hkdf : SecretDerivationPrimitive<HkdfParameters> {
    public companion object Tag : CryptographyProvider.Tag<Hkdf>
}

public class HkdfParameters(
    // TODO?
    public val digest: CryptographyProvider.Tag<SimpleDigest>,
    public val outputSize: Int,
    public val salt: ByteString,
    public val info: ByteString? = null,
)
