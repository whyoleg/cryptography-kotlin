/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules.rsa

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.serialization.*

public class RsaPssAlgorithmIdentifier(override val parameters: RsaPssAlgorithmParameters? = null) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA_PSS
}

@Serializable
public class RsaPssAlgorithmParameters(
    public val hashAlgorithm: HashAlgorithmIdentifier,
    public val maskGenAlgorithm: MaskGenAlgorithmIdentifier,
    public val saltLength: Int = 20,
    public val trailerField: Int = 1,
)

public val ObjectIdentifier.Companion.RSA_PSS: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.10")
