/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.signature


import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SignatureVerifier {
    public suspend fun verifySignature(dataInput: ByteArray, signatureInput: ByteArray): Boolean =
        verifySignatureBlocking(dataInput, signatureInput)

    public fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean
}
