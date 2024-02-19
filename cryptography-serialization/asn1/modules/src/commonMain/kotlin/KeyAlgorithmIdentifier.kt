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

public val ObjectIdentifier.Companion.RSA: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.1")

public object RsaKeyAlgorithmIdentifier : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA
    override val parameters: Nothing? get() = null
}

public val ObjectIdentifier.Companion.EC: ObjectIdentifier get() = ObjectIdentifier("1.2.840.10045.2")

public class EcKeyAlgorithmIdentifier(override val parameters: EcKeyAlgorithmParameters?) : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.EC
}

@Serializable
public class EcKeyAlgorithmParameters(
    public val namedCurve: ObjectIdentifier,
)

public val ObjectIdentifier.Companion.secp521r1: ObjectIdentifier get() = ObjectIdentifier("1.3.132.0.35")
