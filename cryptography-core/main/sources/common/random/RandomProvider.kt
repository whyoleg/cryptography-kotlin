package dev.whyoleg.cryptography.random

import kotlin.random.*

public interface RandomProvider<P> {
    public val defaultRandomParameters: P
    public fun syncRandomizer(parameters: P = defaultRandomParameters): SyncRandomizer
    public fun asyncRandomizer(parameters: P = defaultRandomParameters): AsyncRandomizer

    //TODO: name? needed?
    public fun randomInstance(parameters: P = defaultRandomParameters): Random
}

//TODO: convert SyncRandomizer to kotlin.random.Random
//TODO: seed
