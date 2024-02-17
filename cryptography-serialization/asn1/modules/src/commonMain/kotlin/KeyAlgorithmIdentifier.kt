/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*

@Serializable(KeyAlgorithmIdentifierSerializer::class)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

public class UnknownKeyAlgorithmIdentifier(override val algorithm: ObjectIdentifier) : KeyAlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}

public object RsaKeyAlgorithmIdentifier : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA
    override val parameters: Nothing? get() = null
}

public val ObjectIdentifier.Companion.RSA: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.1")
