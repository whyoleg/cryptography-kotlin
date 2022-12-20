package dev.whyoleg.cryptography.random

import dev.whyoleg.cryptography.*
import kotlin.random.*

public typealias RandomizerProvider<P> = CryptographyOperationProvider<P, Randomizer>
public typealias RandomizerFactory<P> = CryptographyOperationFactory<P, Randomizer>

public interface Randomizer : CryptographyOperation {
    public suspend fun random(size: Int): Buffer
    public suspend fun random(output: Buffer): Buffer
    public fun randomBlocking(size: Int): Buffer
    public fun randomBlocking(output: Buffer): Buffer

    public fun randomInstance(): Random //TODO
}
