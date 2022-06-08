package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*

public interface AesGcm :
    SecretKey,
    KeyEncodePrimitive<SecretKeyFormat>,
    BoxCipherPrimitive<AssociatedData, AesGcmBox> {

    public companion object :
        PrimitiveDecodeParametersProvider<AesGcm, SecretKeyFormat, AesGcmParameters, AesGcmParametersBuilder>,
        PrimitiveGenerateParametersProvider<AesGcm, AesGcmParameters, AesGcmParametersBuilder> {
        override val decodeFactory: AesGcmParametersFactory get() = AesGcmParametersFactory
        override val generateFactory: AesGcmParametersFactory get() = AesGcmParametersFactory
    }
}