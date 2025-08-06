/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

// jws, jwe, jwee
@Serializable(JwaAlgorithmSerializer::class)
public sealed interface JwaAlgorithm {
    public val name: String
}

// TODO: should it be exposed?
private class UnknownJwaAlgorithm(override val name: String) : JwaAlgorithm

// in future, it might be possible to allow customization of algorithms
internal object JwaAlgorithmSerializer : KSerializer<JwaAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "dev.whyoleg.cryptography.serialization.jose.JwaAlgorithm",
        kind = PrimitiveKind.STRING
    )

    override fun serialize(encoder: Encoder, value: JwaAlgorithm) {
        encoder.encodeString(value.name)
    }

    override fun deserialize(decoder: Decoder): JwaAlgorithm {
        val name = decoder.decodeString()
        return JwsAlgorithm.lookupMap[name]
            ?: JweAlgorithm.lookupMap[name]
            ?: JweEncryptionAlgorithm.lookupMap[name]
            ?: UnknownJwaAlgorithm(name)
    }
}
