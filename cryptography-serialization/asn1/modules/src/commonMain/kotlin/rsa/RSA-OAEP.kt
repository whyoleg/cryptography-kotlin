/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules.rsa

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.serialization.*

public class RsaOaepAlgorithmIdentifier(override val parameters: RsaOaepAlgorithmParameters? = null) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA_OAEP
}

@Serializable
public class RsaOaepAlgorithmParameters(
    public val hashFunc: HashAlgorithmIdentifier,
    public val maskGenFunc: MaskGenAlgorithmIdentifier,
    public val pSourceFunc: PSourceAlgorithmIdentifier = PSourceAlgorithmIdentifier(ByteArray(0)), // TODO
)

public val ObjectIdentifier.Companion.RSA_OAEP: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.7")

//      -- AlgorithmIdentifier parameters for id-RSAES-OAEP.
//      -- Note that the tags in this Sequence are explicit.
//
//      RSAES-OAEP-params  ::=  SEQUENCE  {
//         hashFunc          [0] AlgorithmIdentifier DEFAULT sha1Identifier,
//         maskGenFunc       [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
//         pSourceFunc       [2] AlgorithmIdentifier DEFAULT pSpecifiedEmptyIdentifier  }
