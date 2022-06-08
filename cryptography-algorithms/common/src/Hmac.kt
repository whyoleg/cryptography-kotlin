package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.aes.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*
import dev.whyoleg.vio.*

//secret key, mac primitive, export, import, generate
public interface Hmac :
    SecretKey,
    KeyEncodePrimitive<SecretKeyFormat>,
    MacPrimitive {

    public companion object :
        PrimitiveDecodeParametersProvider<Hmac, SecretKeyFormat, HmacParameters, HmacParametersBuilder>,
        PrimitiveGenerateParametersProvider<Hmac, HmacParameters, HmacParametersBuilder> {
        override val decodeFactory: HmacParametersFactory get() = HmacParametersFactory
        override val generateFactory: HmacParametersFactory get() = HmacParametersFactory
    }
}

public object CryptographyAlgorithm {

}


private fun CryptographyProvider.use() {
    decode(CryptographyAlgorithm.HMAC, ByteArray(0).view()) {
        hash(CryptographyAlgorithm.SHA256)
    }

    generate(CryptographyAlgorithm.HMAC) {
        hash(CryptographyAlgorithm.SHA256)
    }

    generate(AesGcm) {

    }
    generate(RsaOaep) {

    }
}
