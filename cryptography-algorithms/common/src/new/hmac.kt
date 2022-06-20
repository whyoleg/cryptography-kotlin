package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.digest.*
import dev.whyoleg.cryptography.key.*

public interface HmacKey : CryptographyKey.Symmetric

public typealias HmacDigestDescriptor<Parameters> = CryptographyPrimitiveDescriptor<Digest, EmptyMaterial, Parameters>

public class HmacKeyGeneratorParameters internal constructor(
    public val descriptor: HmacDigestDescriptor<*>,
) : CryptographyParameters {
    public class Builder internal constructor() {
        internal var descriptor: HmacDigestDescriptor<*> = Sha1DigestDescriptor()
        public fun <Parameters : CryptographyParameters> digest(value: HmacDigestDescriptor<Parameters>) {
            this.descriptor = value
        }

        public inline fun <Parameters : CryptographyParameters, Builder> digest(
            descriptorFactory: CryptographyPrimitiveDescriptorFactory<Digest, EmptyMaterial, Parameters, Builder>,
            block: Builder.() -> Unit = {},
        ) {
            digest(descriptorFactory.invoke(block))
        }

    }


    public companion object : CryptographyParametersFactory<HmacKeyGeneratorParameters, Builder>() {
        override fun createBuilder(): Builder = Builder()
        override fun build(builder: Builder): HmacKeyGeneratorParameters = HmacKeyGeneratorParameters(
            descriptor = builder.descriptor,
        )
    }
}

public typealias HmacBaseKeyGeneratorId<KG> = CryptographyPrimitiveId<KeyGenerator<HmacKey>, KG, EmptyMaterial, HmacKeyGeneratorParameters>
public typealias HmacKeyGeneratorFactory<KG> = CryptographyPrimitiveFactory<KeyGenerator<HmacKey>, KG, EmptyMaterial, HmacKeyGeneratorParameters, HmacKeyGeneratorParameters.Builder>

public val HmacKeyGeneratorAlgorithm: CryptographyPrimitiveAlgorithm<KeyGenerator<HmacKey>, EmptyMaterial, HmacKeyGeneratorParameters>
    get() = CryptographyPrimitiveAlgorithm("HMAC|KEY-GENERATOR")
public val HmacKeyGeneratorDescriptor: CryptographyPrimitiveDescriptorFactory<KeyGenerator<HmacKey>, EmptyMaterial, HmacKeyGeneratorParameters, HmacKeyGeneratorParameters.Builder>
    get() = CryptographyPrimitiveDescriptorFactory(HmacKeyGeneratorAlgorithm, HmacKeyGeneratorParameters)

public val HmacKeyGeneratorId: HmacBaseKeyGeneratorId<KeyGenerator.Sync<HmacKey>>
    get() = CryptographyPrimitiveId(HmacKeyGeneratorAlgorithm, "SYNC")

public val HmacAsyncKeyGeneratorId: HmacBaseKeyGeneratorId<KeyGenerator.Async<HmacKey>>
    get() = CryptographyPrimitiveId(HmacKeyGeneratorAlgorithm, "ASYNC")

public val HmacKeyGenerator: HmacKeyGeneratorFactory<KeyGenerator.Sync<HmacKey>>
    get() = HmacKeyGeneratorFactory(HmacKeyGeneratorId, HmacKeyGeneratorParameters)

public val HmacAsyncKeyGenerator: HmacKeyGeneratorFactory<KeyGenerator.Async<HmacKey>>
    get() = HmacKeyGeneratorFactory(HmacAsyncKeyGeneratorId, HmacKeyGeneratorParameters)




private suspend fun CryptographyProvider.testhmac() {
    val generator = HmacKeyGenerator(EmptyMaterial) {
        digest(Sha1DigestDescriptor)
    }
    val key = generator.generateKey()

//    val signature = HmacSignature2(key)
//    val result = signature.sign(ByteArray(100).view())
//
//    val bool = HmacStreamSignature(key).verify {
//        verifyFinalPart(result)
//    }
}
