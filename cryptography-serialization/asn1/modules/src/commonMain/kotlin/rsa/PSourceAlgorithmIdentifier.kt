/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules.rsa

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.encoding.*

// TODO: is it optional?
@Serializable(PSourceAlgorithmIdentifierSerializer::class)
public class PSourceAlgorithmIdentifier(override val parameters: ByteArray?) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.pSpecified
}

internal object PSourceAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer<PSourceAlgorithmIdentifier>() {
    override fun CompositeEncoder.encodeParameters(value: PSourceAlgorithmIdentifier) {
        encodeParameters(ByteArraySerializer(), value.parameters)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): PSourceAlgorithmIdentifier {
        check(algorithm == ObjectIdentifier.pSpecified) { "Wrong OID, expected ${ObjectIdentifier.pSpecified.value}, received: ${algorithm.value}" }
        return PSourceAlgorithmIdentifier(decodeParameters(ByteArraySerializer()))
    }
}

internal val ObjectIdentifier.Companion.pSpecified: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.9")
