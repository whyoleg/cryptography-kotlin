package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public sealed interface AesParameters : CryptographyParameters {
    public val keySize: KeySize
}

public sealed interface AesParametersBuilder<P : AesParameters> : CryptographyParametersBuilder<P> {
    public fun keySize(value: KeySize)
}

public class AesGcmBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext,
    public val authTag: AuthTag
) : CipherBox(ciphertext)

public sealed interface AesGcmParameters : AesParameters {
    public val padding: Boolean //or enum?
    public val tagSize: BinarySize
}

public sealed interface AesGcmParametersBuilder : AesParametersBuilder<AesGcmParameters> {
    public fun padding(value: Boolean)
    public fun tagSize(value: BinarySize)
}

//TODO: can be replaced with vals?
public object AesGcmParametersFactory : CryptographyParametersFactory<AesGcmParameters, AesGcmParametersBuilder>(
    createBuilder = ::AesGcmParametersImpl,
    build = { it as AesGcmParameters }
)

private class AesGcmParametersImpl : AesGcmParameters, AesGcmParametersBuilder {
    override var keySize: KeySize = KeySize(128.bits)
    override var padding: Boolean = true
    override var tagSize: BinarySize = 96.bits

    override fun keySize(value: KeySize) {
        keySize = value
    }

    override fun padding(value: Boolean) {
        padding = value
    }

    override fun tagSize(value: BinarySize) {
        tagSize = value
    }
}
