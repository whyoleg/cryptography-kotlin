package dev.whyoleg.cryptography.algorithms.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.hash.*

public sealed interface SHA3 : HashProvider<SHA3.Parameters> {
    public sealed class Parameters : CryptographyParameters

    public companion object {
        public val B224: Int = TODO()
    }

    public interface B512 : SHA3 {
        public companion object : CryptographyAlgorithm<B>
    }

//    public object B224 : SHA3() {
//        override val defaultHashParameters: SHA3 get() = this
//    }
//
//    public object B512 : SHA3() //etc
}

public abstract class SHAKE128 : HashProvider<SHAKE128.Parameters> {
    public companion object : CryptographyAlgorithm<SHAKE128>

    final override val defaultHashParameters: Parameters get() = Parameters.Default

    public class Parameters(
        public val digestSize: BinarySize = 128.bytes,
    ) : CopyableCryptographyParameters<Parameters, Parameters.Builder>() {
        override fun builder(): Builder = Builder(digestSize)
        override fun build(builder: Builder): Parameters = Parameters(builder.digestSize)
        public class Builder internal constructor(
            public var digestSize: BinarySize,
        )

        public companion object {
            public val Default: Parameters = Parameters()
        }
    }
}

private fun test(engine: CryptographyEngine) {
    val shake = engine.get(SHAKE128)

    val hasher = shake.syncHasher {
        digestSize = 256.bytes
    }

    hasher.hash(ByteArray(10))
}
