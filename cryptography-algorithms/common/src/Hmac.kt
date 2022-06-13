package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.aes.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*
import dev.whyoleg.cryptography.signature.*
import dev.whyoleg.vio.*

//public interface Hmac :
//    SecretKeyPrimitive,
//    KeyEncodePrimitive<SecretKeyFormat>,
//    MacPrimitive {
//
//    public companion object :
//        CryptographyAlgorithm<Hmac>,
//        CryptographyAlgorithm.ForKeyDecode<SecretKeyFormat, Hmac, HmacParameters, HmacParametersBuilder>,
//        CryptographyAlgorithm.ForGenerate<Hmac, HmacParameters, HmacParametersBuilder> {
//        override fun builderForGenerate(): HmacParametersBuilder = HmacParametersImpl()
//        override fun builderForKeyDecode(): HmacParametersBuilder = HmacParametersImpl()
//    }
//}
//
//public sealed interface HmacParameters : CryptographyParameters {
//    public val hash: HashParameters
//}
//
//public sealed interface HmacParametersBuilder : CryptographyParametersBuilder<HmacParameters> {
//    public fun hash(value: HashParameters)
//}
//
//private class HmacParametersImpl : HmacParameters, HmacParametersBuilder {
//    override var hash: HashParameters = Sha1Parameters
//
//    override fun hash(value: HashParameters) {
//        hash = value
//    }
//
//    override fun build(): HmacParameters = this
//}
