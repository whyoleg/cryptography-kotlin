package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.digest.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import dev.whyoleg.vio.*

public class ShakeParameters(
    public val digestSize: BinarySize,
) : CryptographyParameters {
    public class Builder internal constructor() {
        internal var digestSize: BinarySize = 10.bytes //TODO
        public fun digestSize(value: BinarySize) {
            digestSize = value
        }
    }

    public companion object : CryptographyParametersFactory<ShakeParameters, Builder>() {
        override fun createBuilder(): Builder = Builder()
        override fun build(builder: Builder): ShakeParameters = ShakeParameters(builder.digestSize)
    }
}

public val Shake128: CryptographyAlgorithm<BaseHasher, ShakeParameters, ShakeParameters.Builder> =
    CryptographyAlgorithm("SHAKE128", ShakeParameters)

public val Shake256: CryptographyAlgorithm<BaseHasher, ShakeParameters, ShakeParameters.Builder> =
    CryptographyAlgorithm("SHAKE256", ShakeParameters)

public inline fun CP.Shake128Hasher(block: ShakeParameters.Builder.() -> Unit = {}): Hasher {
    return Shake128.from(Hasher, ShakeParameters(block))
}

public class HmacKeyGenParameters(
//    public val
) : CryptographyParameters {
    public class Builder
}

public val HmacKeyGenerator: CryptographyAlgorithm<KeyGenerator<HmacKey>, HmacKeyGenParameters, HmacKeyGenParameters.Builder> =
    CryptographyAlgorithm("HMAC|KEY-GENERATOR", TODO())

public class HmacParameters(
    public val key: HmacKey,
) : CryptographyParameters

public val Hmac: CryptographyAlgorithm<Signature, HmacParameters, Unit>

private suspend fun CP.use() {
    val hasher = Shake128(AsyncHasher, ShakeParameters(3.bytes))

    AsyncHasher.from(Shake128, ShakeParameters(3.bytes))

    SyncKeyGenerator<HmacKey>().from(Shake128, ShakeParameters(3.bytes))

    HmacKeyGenerator(SyncKeyGenerator(), ShakeParameters(3.bytes))

    hasher.hashAsync(ByteArray(10).view())

    val parameters = ShakeParameters {
        digestSize(10.bytes)
    }

    val sh = Shake256(Hasher) {

    }

    val sh2 = Shake128Hasher {

    }

    HmacKeyGenerator(SyncKeyGenerator) {

    }

    val generator: KeyGenerator.Sync<HmacKey> = HmacKeyGenerator.from(TODO(), HmacKeyGenParameters())

    val key = generator.generateKey()

    Hmac.from(SyncSignature, HmacParameters(key))
    Hmac.from(SyncSignature, key)

    Hmac(SyncSignature, key)

    val key = RsaKeyGenerator(KeyGenerator::Sync)

    //sync + boxSync, async + boxAsync, stream + boxStream(NOT YET)
    //RSA - box and stream has no sense
    //AES GCM - everything is fine

    RsaOaep(Encryptor::Async, key.publicKey)

    //not supported
    RsaOaep(StreamEncryptor, key.publicKey)

    RsaOaepDecryptor(Decryptor::Sync, key.privateKey)

    AesGcm(Encryptor::Async, secretKey)
    AesGcm(Encryptor::Sync, secretKey)
    AesGcm(Cipher::Sync, secretKey)
    AesGcm(StreamEncryptor, secretKey)
    AesGcm(StreamCipher, secretKey)
    AesGcm(BoxCipher::Sync, secretKey)

    Rsa(KeyPairGenerator::Sync)
    Rsa(PublicKeyDecoder::Sync)
    Rsa(PublicKeyEncoder::Async)

    Hmac(KeyGenerator::Sync)

    Hmac(Signature::Async)
}

public val TestAlg: CryptographyAlgorithm<TestPrimitive, EmptyParameters, Unit> =
    CryptographyAlgorithm("TEST", EmptyParameters)

public val TestGAlg: CryptographyAlgorithm<TestGPrimitive<*>, EmptyParameters, Unit> =
    CryptographyAlgorithm("TESTG", EmptyParameters)

public val TestGAlg2: CryptographyAlgorithm<TestGPrimitive<Int>, EmptyParameters, Unit> =
    CryptographyAlgorithm("TESTG", EmptyParameters)

private fun CP.tests() {
    val s1 = TestAlg.from(SyncTestPrimitive, EmptyParameters)
    val s2 = TestAlg(SyncTestPrimitive)

    val sg1 = TestGAlg.from(SyncTestGPrimitive.of<String>(), EmptyParameters)
    val sg2 = TestGAlg(SyncTestGPrimitive.of<String>())
    val sg12 = TestGAlg2.from(SyncTestGPrimitive.of(), EmptyParameters)
    val sg22 = TestGAlg2(SyncTestGPrimitive.of())
}

public interface TestGPrimitive<T> : CryptographyPrimitive
public interface SyncTestGPrimitive<T> : TestGPrimitive<T> {
    public companion object {
        public inline fun <T> of(): CryptographyPrimitiveId<SyncTestGPrimitive<T>> = TODO()
    }
}

public interface AsyncTestGPrimitive<T> : TestGPrimitive<T> {
    public companion object {
        public inline fun <T> of(): CryptographyPrimitiveId<AsyncTestGPrimitive<T>> = TODO()
    }
}

public interface TestPrimitive : CryptographyPrimitive
public interface SyncTestPrimitive : TestPrimitive {
    public companion object : CryptographyPrimitiveId<SyncTestPrimitive>
}

public interface AsyncTestPrimitive : TestPrimitive {
    public companion object : CryptographyPrimitiveId<AsyncTestPrimitive>
}


