/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import kotlinx.io.bytestring.*

public interface SecretDerivationPrimitive<P> {
    public fun deriveSecret(input: ByteString, parameters: P): ByteString
}

public interface AsyncSecretDerivationPrimitive<P> {
    public suspend fun deriveSecret(input: ByteString, parameters: P): ByteString
}
