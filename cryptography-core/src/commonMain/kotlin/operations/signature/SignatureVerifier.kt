/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public suspend fun verifySignature(data: ByteArray, signature: ByteArray): Boolean = verifySignatureBlocking(data, signature)
    public fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean

    public suspend fun verifySignature(data: ByteString, signature: ByteString): Boolean =
        verifySignature(data.asByteArray(), signature.asByteArray())

    public fun verifySignatureBlocking(data: ByteString, signature: ByteString): Boolean =
        verifySignatureBlocking(data.asByteArray(), signature.asByteArray())
}
