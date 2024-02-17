/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*

@Serializable
public class SubjectPublicKeyInfo(
    @Contextual
    public val algorithm: KeyAlgorithmIdentifier,
    public val subjectPublicKey: BitArray,
)

@Serializable
public class PrivateKeyInfo(
    public val version: Int,
    @Contextual
    public val privateKeyAlgorithm: KeyAlgorithmIdentifier,
    public val privateKey: ByteArray,
    // TODO: attributes
)
