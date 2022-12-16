package dev.whyoleg.cryptography.random

import dev.whyoleg.cryptography.*

public interface Randomizer

public interface SyncRandomizer : Randomizer {
    public fun random(size: Int): Buffer
    public fun random(output: Buffer): Buffer
}

public interface AsyncRandomizer : Randomizer {
    public suspend fun random(size: Int): Buffer
    public suspend fun random(output: Buffer): Buffer
}

//TODO: convert SynncRandomizer to kotlin.random.Random
//TODO: seed
