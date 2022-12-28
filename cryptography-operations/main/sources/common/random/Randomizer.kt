@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.operations.random

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import kotlin.random.*

public typealias RandomizerProvider<P> = CryptographyOperationProvider<P, Randomizer>
public typealias RandomizerFactory<P> = CryptographyOperationFactory<P, Randomizer>

//seed support
public interface Randomizer : CryptographyOperation {
    //TODO: rename to randomBytes?
    public suspend fun random(size: Int): Buffer
    public suspend fun random(output: Buffer): Buffer
    public fun randomBlocking(size: Int): Buffer
    public fun randomBlocking(output: Buffer): Buffer

    //TODO name
    public fun randomInstance(): Random
}
