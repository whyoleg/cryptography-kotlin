package dev.whyoleg.cryptography

//TODO: is it needed at all?
public interface CryptographyAlgorithm

public open class CryptographyAlgorithmIdentifier<A : CryptographyAlgorithm>(public val name: String)

public interface CryptographyAlgorithmProvider {
    public fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A
}
