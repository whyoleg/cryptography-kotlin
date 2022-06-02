package dev.whyoleg.cryptography.random

import dev.whyoleg.vio.*

//TODO: correct interface
public interface CryptographyRandom {
    public val async: Async

    public fun nextBytes(output: BufferView)

    //is it needed?
    //f.e. on nodejs it can be needed
    //TODO algorithms?
    public interface Async {
        public suspend fun nextBytes(output: BufferView)
    }
}
