package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public interface KeyEncodePrimitive<F : KeyFormat> {
    public fun encode(format: F): BufferView
    public fun encode(format: F, output: BufferView): BufferView
    public suspend fun encodeSuspend(format: F): BufferView
    public suspend fun encodeSuspend(format: F, output: BufferView): BufferView
}

//stores locally: f.e. android keychain or ios/mac keychain or windows keychain?
// or file? or remote?
public interface KeyStorePrimitive {

}
