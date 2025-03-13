/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import kotlinx.io.bytestring.*

public interface SecretDerivationPrimitive {
    public val defaultSecretSize: Int

    public fun deriveSecret(input: ByteString, secretSize: Int = defaultSecretSize): ByteString
}
