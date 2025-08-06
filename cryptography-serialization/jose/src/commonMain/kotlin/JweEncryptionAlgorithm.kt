/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

public fun JweEncryptionAlgorithm(name: String): JweEncryptionAlgorithm {
    return JweEncryptionAlgorithm.lookupMap[name] ?: JweEncryptionAlgorithm(name, null)
}

@Serializable(JweEncryptionAlgorithmSerializer::class)
public class JweEncryptionAlgorithm internal constructor(
    override val name: String,
    @Suppress("UNUSED_PARAMETER") dummy: Any?,
) : JwaAlgorithm {
    override fun toString(): String = "JweEncryptionAlgorithm($name)"
    override fun equals(other: Any?): Boolean = this === other || other is JweEncryptionAlgorithm && name == other.name
    override fun hashCode(): Int = name.hashCode()

    public companion object {
        public val A128CBC_HS256: JweEncryptionAlgorithm = JweEncryptionAlgorithm("A128CBC-HS256", null)
        public val A192CBC_HS384: JweEncryptionAlgorithm = JweEncryptionAlgorithm("A192CBC-HS384", null)
        public val A256CBC_HS512: JweEncryptionAlgorithm = JweEncryptionAlgorithm("A256CBC-HS512", null)

        public val A128GCM: JweEncryptionAlgorithm = JweEncryptionAlgorithm("A128GCM", null)
        public val A192GCM: JweEncryptionAlgorithm = JweEncryptionAlgorithm("A192GCM", null)
        public val A256GCM: JweEncryptionAlgorithm = JweEncryptionAlgorithm("A256GCM", null)

        internal val lookupMap = listOf(
            A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
            A128GCM, A192GCM, A256GCM,
        ).associateBy(JweEncryptionAlgorithm::name)
    }
}

internal object JweEncryptionAlgorithmSerializer : KSerializer<JweEncryptionAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "dev.whyoleg.cryptography.serialization.jose.JweEncryptionAlgorithm",
        kind = PrimitiveKind.STRING
    )

    override fun serialize(encoder: Encoder, value: JweEncryptionAlgorithm): Unit = encoder.encodeString(value.name)
    override fun deserialize(decoder: Decoder): JweEncryptionAlgorithm = JweEncryptionAlgorithm(decoder.decodeString())
}
