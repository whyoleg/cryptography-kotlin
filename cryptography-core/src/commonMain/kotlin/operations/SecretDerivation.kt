/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation {
    public suspend fun deriveSecret(input: ByteArray): ByteArray {
        return deriveSecretBlocking(input)
    }

    public suspend fun deriveSecret(input: ByteString): ByteString {
        return deriveSecret(input.asByteArray()).asByteString()
    }

    public fun deriveSecretBlocking(input: ByteArray): ByteArray

    public fun deriveSecretBlocking(input: ByteString): ByteString {
        return deriveSecretBlocking(input.asByteArray()).asByteString()
    }
}
