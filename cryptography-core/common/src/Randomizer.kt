package dev.whyoleg.cryptography

import dev.whyoleg.vio.*
import kotlin.random.*

//TODO: what is correct name?
public interface Randomizer
public interface SyncRandomizer : Randomizer {
    public fun random(): BufferView
    public fun random(output: BufferView): BufferView
}

public interface AsyncRandomizer : Randomizer {
    public suspend fun randomAsync(): BufferView
    public suspend fun randomAsync(output: BufferView): BufferView
}

//TODO: better name like KotlinRandomPrimitive
public interface InstanceRandomizer : Randomizer {
    public val instance: SecureRandom
}


//TODO: decide on reseed methods
public abstract class SecureRandom : Random() {
    public abstract fun reseed(): SecureRandom //TODO!!!
}
