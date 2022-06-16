package dev.whyoleg.cryptography.random

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

//TODO: what is correct name?
public interface Randomizer : CryptographyPrimitive {
    public interface Sync : Randomizer {
        public fun random(): BufferView
        public fun random(output: BufferView): BufferView
    }

    public interface Async : Randomizer {
        public suspend fun random(): BufferView
        public suspend fun random(output: BufferView): BufferView
    }

    //TODO: better name like KotlinRandomPrimitive
    public interface Instance : Randomizer {
        public val instance: SecureRandom
    }

}
