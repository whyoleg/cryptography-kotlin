package dev.whyoleg.cryptography.provider

import dev.whyoleg.cryptography.algorithms.*

@SubclassOptInRequired(ProviderApi::class)
public abstract class CryptographyProvider(
    public val name: String,
) {
    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?
    public open fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A =
        getOrNull(identifier) ?: throw CryptographyAlgorithmNotFoundException(identifier)

    public companion object
}

//public abstract class CryptographyEngineBuilder {
//    public fun <A : CryptographyAlgorithm> register(
//        identifier: CryptographyAlgorithmIdentifier<A>,
//        block: () -> A,
//    ): Unit {
//
//    }
//}
//
//public abstract class MapCryptographyEngine(
//    engineId: CryptographyProviderId,
//) : CryptographyProvider(engineId) {
//
//}
