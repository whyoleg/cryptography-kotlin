package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.digest.*
import dev.whyoleg.vio.*

public class ShakeDigestParameters internal constructor(
    public val digestSize: BinarySize,
) : CryptographyParameters {
    public class Builder internal constructor() {
        internal var digestSize: BinarySize = 10.bytes //TODO
        public fun digestSize(value: BinarySize) {
            digestSize = value
        }
    }

    public companion object : CryptographyParametersFactory<ShakeDigestParameters, Builder>() {
        override fun createBuilder(): Builder = Builder()
        override fun build(builder: Builder): ShakeDigestParameters = ShakeDigestParameters(builder.digestSize)
    }
}

public typealias ShakeDigestAlgorithm = CryptographyPrimitiveAlgorithm<Digest, EmptyMaterial, ShakeDigestParameters>
public typealias ShakeDigestDescriptorFactory = CryptographyPrimitiveDescriptorFactory<Digest, EmptyMaterial, ShakeDigestParameters, ShakeDigestParameters.Builder>
public typealias ShakeDigestId<D> = CryptographyPrimitiveId<Digest, D, EmptyMaterial, ShakeDigestParameters>
public typealias ShakeDigestFactory<D> = CryptographyPrimitiveFactory<Digest, D, EmptyMaterial, ShakeDigestParameters, ShakeDigestParameters.Builder>


public val Shake128DigestAlgorithm: ShakeDigestAlgorithm get() = ShakeDigestAlgorithm("SHAKE128")
public val Shake128DigestDescriptor: ShakeDigestDescriptorFactory
    get() = ShakeDigestDescriptorFactory(Shake128DigestAlgorithm, ShakeDigestParameters)

public val Shake128DigestId: ShakeDigestId<Digest.Sync> get() = ShakeDigestId(Shake128DigestAlgorithm, "SYNC")
public val Shake128AsyncDigestId: ShakeDigestId<Digest.Async> get() = ShakeDigestId(Shake128DigestAlgorithm, "ASYNC")
public val Shake128StreamDigestId: ShakeDigestId<Digest.Stream> get() = ShakeDigestId(Shake128DigestAlgorithm, "STREAM")

public val Shake128Digest: ShakeDigestFactory<Digest.Sync> get() = ShakeDigestFactory(Shake128DigestId, ShakeDigestParameters)
public val Shake128AsyncDigest: ShakeDigestFactory<Digest.Async> get() = ShakeDigestFactory(Shake128AsyncDigestId, ShakeDigestParameters)
public val Shake128StreamDigest: ShakeDigestFactory<Digest.Stream> get() = ShakeDigestFactory(Shake128StreamDigestId, ShakeDigestParameters)

public val Shake256DigestAlgorithm: ShakeDigestAlgorithm get() = ShakeDigestAlgorithm("SHAKE256")
public val Shake256DigestDescriptor: ShakeDigestDescriptorFactory
    get() = ShakeDigestDescriptorFactory(Shake256DigestAlgorithm, ShakeDigestParameters)

public val Shake256DigestId: ShakeDigestId<Digest.Sync> get() = ShakeDigestId(Shake256DigestAlgorithm, "SYNC")
public val Shake256AsyncDigestId: ShakeDigestId<Digest.Async> get() = ShakeDigestId(Shake256DigestAlgorithm, "ASYNC")
public val Shake256StreamDigestId: ShakeDigestId<Digest.Stream> get() = ShakeDigestId(Shake256DigestAlgorithm, "STREAM")

public val Shake256Digest: ShakeDigestFactory<Digest.Sync> get() = ShakeDigestFactory(Shake256DigestId, ShakeDigestParameters)
public val Shake256AsyncDigest: ShakeDigestFactory<Digest.Async> get() = ShakeDigestFactory(Shake256AsyncDigestId, ShakeDigestParameters)
public val Shake256StreamDigest: ShakeDigestFactory<Digest.Stream> get() = ShakeDigestFactory(Shake256StreamDigestId, ShakeDigestParameters)

private fun CryptographyProvider.s() {
    val parameters = ShakeDigestParameters {

    }
    val d = get(Shake128DigestId, EmptyMaterial, parameters)

    val d2 = Shake128Digest.from(EmptyMaterial, parameters)
    val digest = Shake128Digest(EmptyMaterial)

    val result = digest.hash(ByteArray(10).view())
}
