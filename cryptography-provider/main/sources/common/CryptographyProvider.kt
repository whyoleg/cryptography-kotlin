package dev.whyoleg.cryptography.provider

public abstract class CryptographyProvider(
    public val name: String,
) {
    public abstract fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A

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
