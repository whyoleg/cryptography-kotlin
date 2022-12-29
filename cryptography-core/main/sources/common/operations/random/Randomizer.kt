package dev.whyoleg.cryptography.operations.random

import dev.whyoleg.cryptography.io.*
import kotlin.random.*

//TODO: move out from operations?
//seed support
public interface Randomizer {
    //TODO: rename to randomBytes?
    public suspend fun random(size: Int): Buffer
    public suspend fun random(output: Buffer): Buffer
    public fun randomBlocking(size: Int): Buffer
    public fun randomBlocking(output: Buffer): Buffer

    //TODO name
    public fun randomInstance(): Random
}
