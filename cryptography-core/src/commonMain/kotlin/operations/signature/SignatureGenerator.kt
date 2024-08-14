/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.signature


import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureGenerator {
    public suspend fun generateSignature(data: ByteArray): ByteArray = generateSignatureBlocking(data)
    public fun generateSignatureBlocking(data: ByteArray): ByteArray
}
