/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

public fun JweAlgorithm(name: String): JweAlgorithm {
    return JweAlgorithm.lookupMap[name] ?: JweAlgorithm(name, null)
}

@Serializable(JweAlgorithmSerializer::class)
public class JweAlgorithm internal constructor(
    override val name: String,
    @Suppress("UNUSED_PARAMETER") dummy: Any?,
) : JwaAlgorithm {
    override fun toString(): String = "JweAlgorithm($name)"
    override fun equals(other: Any?): Boolean = this === other || other is JweAlgorithm && name == other.name
    override fun hashCode(): Int = name.hashCode()

    public companion object {
        public val RSA1_5: JweAlgorithm = JweAlgorithm("RSA1_5", null)
        public val RSA_OAEP: JweAlgorithm = JweAlgorithm("RSA-OAEP", null)
        public val RSA_OAEP_256: JweAlgorithm = JweAlgorithm("RSA-OAEP-256", null)

        public val A128KW: JweAlgorithm = JweAlgorithm("A128KW", null)
        public val A192KW: JweAlgorithm = JweAlgorithm("A192KW", null)
        public val A256KW: JweAlgorithm = JweAlgorithm("A256KW", null)

        public val DIRECT: JweAlgorithm = JweAlgorithm("dir", null)

        public val ECDH_ES: JweAlgorithm = JweAlgorithm("ECDH-ES", null)

        public val ECDH_ES_A128KW: JweAlgorithm = JweAlgorithm("ECDH-ES+A128KW", null)
        public val ECDH_ES_A192KW: JweAlgorithm = JweAlgorithm("ECDH-ES+A192KW", null)
        public val ECDH_ES_A256KW: JweAlgorithm = JweAlgorithm("ECDH-ES+A256KW", null)

        public val A128GCMKW: JweAlgorithm = JweAlgorithm("A128GCMKW", null)
        public val A192GCMKW: JweAlgorithm = JweAlgorithm("A192GCMKW", null)
        public val A256GCMKW: JweAlgorithm = JweAlgorithm("A256GCMKW", null)

        public val PBES2_HS256_A128KW: JweAlgorithm = JweAlgorithm("PBES2-HS256+A128KW", null)
        public val PBES2_HS384_A192KW: JweAlgorithm = JweAlgorithm("PBES2-HS384+A192KW", null)
        public val PBES2_HS512_A256KW: JweAlgorithm = JweAlgorithm("PBES2-HS512+A256KW", null)

        internal val lookupMap = listOf(
            RSA1_5, RSA_OAEP, RSA_OAEP_256,
            A128KW, A192KW, A256KW,
            DIRECT,
            ECDH_ES,
            ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
            A128GCMKW, A192GCMKW, A256GCMKW,
            PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW,
        ).associateBy(JweAlgorithm::name)
    }
}

internal object JweAlgorithmSerializer : KSerializer<JweAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "dev.whyoleg.cryptography.serialization.jose.JweAlgorithm",
        kind = PrimitiveKind.STRING
    )

    override fun serialize(encoder: Encoder, value: JweAlgorithm): Unit = encoder.encodeString(value.name)
    override fun deserialize(decoder: Decoder): JweAlgorithm = JweAlgorithm(decoder.decodeString())
}
