package dev.whyoleg.cryptography.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface DigestProvider {
    public fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters,
            > get(
        id: CPId<Primitive>,
        parameters: Parameters,
    ): Primitive
}

//TODO: decide on function and class names
public interface Digest : CryptographyPrimitive {
    public interface Sync : Digest {
        public companion object Id : CPId<Sync>

        public val digestSize: BinarySize

        public fun hash(input: BufferView): BufferView
        public fun hash(input: BufferView, digestOutput: BufferView): BufferView
    }

    public interface Async : Digest {
        public val digestSize: BinarySize

        public suspend fun hash(input: BufferView): BufferView
        public suspend fun hash(input: BufferView, digestOutput: BufferView): BufferView
    }

    public interface Stream : Digest {
        public fun createDigestFunction(): DigestFunction
    }
}

//BaseDigest
//Digest:BaseDigest
//AsyncDigest:BaseDigest
//StreamDigest:BaseDigest
