/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@Serializable(KeyAlgorithmIdentifierSerializer::class)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

public class UnknownKeyAlgorithmIdentifier(override val algorithm: ObjectIdentifier) : KeyAlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}

// custom serializer
public sealed interface KeyAlgorithmIdentifier2 {
    public val algorithm: ObjectIdentifier

    public data object RSA : KeyAlgorithmIdentifier2 {
        override val algorithm: ObjectIdentifier get() = ObjectIdentifier.rsaEncryption
    }

    public data class EC(val parameters: EcParameters?) : KeyAlgorithmIdentifier2 {
        override val algorithm: ObjectIdentifier get() = TODO("Not yet implemented")
    }

    // those could be overridden by users
    public interface Unknown : KeyAlgorithmIdentifier2
}

public val ObjectIdentifier.Companion.rsaEncryption: ObjectIdentifier get() = ObjectIdentifier.parse("1.2.840.113549.1.1.1")

private class RsaSer : KSerializer<KeyAlgorithmIdentifier2.RSA> {
    override val descriptor: SerialDescriptor
        get() = TODO("Not yet implemented")

    override fun serialize(
        encoder: Encoder,
        value: KeyAlgorithmIdentifier2.RSA,
    ) {
        encoder.encodeNull()
    }

    override fun deserialize(decoder: Decoder): KeyAlgorithmIdentifier2.RSA {
        require(!decoder.decodeNotNullMark())
        decoder.decodeNull()
        // TODO?
        return KeyAlgorithmIdentifier2.RSA
    }
}
