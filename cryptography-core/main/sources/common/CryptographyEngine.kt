package dev.whyoleg.cryptography

import kotlin.jvm.*

@JvmInline
public value class CryptographyEngineId(public val name: String)

public abstract class CryptographyEngine(
    public val engineId: CryptographyEngineId,
) {
    public abstract fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A

    public companion object
}

//TODO before release
public abstract class CryptographyEngineBuilder {
    public fun <A : CryptographyAlgorithm> register(
        identifier: CryptographyAlgorithmIdentifier<A>,
        block: () -> A,
    ): Unit {

    }
}

public abstract class MapCryptographyEngine(
    engineId: CryptographyEngineId,
) : CryptographyEngine(engineId) {

}
