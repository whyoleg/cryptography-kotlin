/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.encoding.*

@Serializable(PSourceAlgorithmIdentifierSerializer::class)
public class PSourceAlgorithmIdentifier(override val parameters: ByteArray?) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = TODO("Not yet implemented") // id-pSpecified
}

public object PSourceAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer<PSourceAlgorithmIdentifier>() {
    override fun CompositeEncoder.encodeParameters(value: PSourceAlgorithmIdentifier) {
        encodeParameters(ByteArraySerializer(), value.parameters)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): PSourceAlgorithmIdentifier {
        check(algorithm == ObjectIdentifier("")) // TODO
        return PSourceAlgorithmIdentifier(decodeParameters(ByteArraySerializer()))
    }
}
