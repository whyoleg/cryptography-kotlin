/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

public fun JwsAlgorithm(name: String): JwsAlgorithm {
    return JwsAlgorithm.lookupMap[name] ?: JwsAlgorithm(name, null)
}

@Serializable(JwsAlgorithmSerializer::class)
public class JwsAlgorithm internal constructor(
    override val name: String,
    @Suppress("UNUSED_PARAMETER") dummy: Any?,
) : JwaAlgorithm {
    override fun toString(): String = "JwsAlgorithm($name)"
    override fun equals(other: Any?): Boolean = this === other || other is JwsAlgorithm && name == other.name
    override fun hashCode(): Int = name.hashCode()

    public companion object {
        public val HS256: JwsAlgorithm = JwsAlgorithm("HS256", null)
        public val HS384: JwsAlgorithm = JwsAlgorithm("HS384", null)
        public val HS512: JwsAlgorithm = JwsAlgorithm("HS512", null)

        public val RS256: JwsAlgorithm = JwsAlgorithm("RS256", null)
        public val RS384: JwsAlgorithm = JwsAlgorithm("RS384", null)
        public val RS512: JwsAlgorithm = JwsAlgorithm("RS512", null)

        public val PS256: JwsAlgorithm = JwsAlgorithm("PS256", null)
        public val PS384: JwsAlgorithm = JwsAlgorithm("PS384", null)
        public val PS512: JwsAlgorithm = JwsAlgorithm("PS512", null)

        public val ES256: JwsAlgorithm = JwsAlgorithm("ES256", null)
        public val ES384: JwsAlgorithm = JwsAlgorithm("ES384", null)
        public val ES512: JwsAlgorithm = JwsAlgorithm("ES512", null)

        public val none: JwsAlgorithm = JwsAlgorithm("none", null)

        internal val lookupMap = listOf(
            HS256, HS384, HS512,
            RS256, RS384, RS512,
            PS256, PS384, PS512,
            ES256, ES384, ES512,
            none,
        ).associateBy(JwsAlgorithm::name)
    }
}

internal object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "dev.whyoleg.cryptography.serialization.jose.JwsAlgorithm",
        kind = PrimitiveKind.STRING
    )

    override fun serialize(encoder: Encoder, value: JwsAlgorithm): Unit = encoder.encodeString(value.name)
    override fun deserialize(decoder: Decoder): JwsAlgorithm = JwsAlgorithm(decoder.decodeString())
}
