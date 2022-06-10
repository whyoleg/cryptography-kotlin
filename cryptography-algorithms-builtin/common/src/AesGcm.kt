package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*

//TODO: may be we need to split aes per key size right here, instead of field keySize!!!
public interface AesGcm :
    SecretKey,
    KeyEncodePrimitive<SymmetricKeyFormat>,
    BoxCipherPrimitive<AssociatedData, AesGcmBox> {

    public companion object :
        PrimitiveDecodeParametersProvider<AesGcm, SymmetricKeyFormat, AesGcmParameters, AesGcmParametersBuilder>,
        PrimitiveGenerateParametersProvider<AesGcm, AesGcmParameters, AesGcmParametersBuilder> {
        override val decodeFactory: AesGcmParametersFactory get() = AesGcmParametersFactory
        override val generateFactory: AesGcmParametersFactory get() = AesGcmParametersFactory
    }
}