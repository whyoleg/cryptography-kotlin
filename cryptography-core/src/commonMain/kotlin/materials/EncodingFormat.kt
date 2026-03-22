/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*

/**
 * Represents a format used for encoding and decoding cryptographic materials such as keys or parameters.
 * Common formats include DER, PEM, JWK, and RAW.
 *
 * Used by [Encodable] for encoding and [Decoder] for decoding cryptographic materials.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodingFormat {
    /**
     * A human-readable name identifying this encoding format.
     */
    public val name: String
    override fun toString(): String
}
