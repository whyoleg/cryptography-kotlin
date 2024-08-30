/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SecretDerivation {
    public suspend fun deriveSecret(input: ByteArray): ByteArray = deriveSecretBlocking(input)
    public fun deriveSecretBlocking(input: ByteArray): ByteArray

    public suspend fun deriveSecret(input: ByteString): ByteString = deriveSecret(input.asByteArray()).asByteString()
    public fun deriveSecretBlocking(input: ByteString): ByteString = deriveSecretBlocking(input.asByteArray()).asByteString()
}
