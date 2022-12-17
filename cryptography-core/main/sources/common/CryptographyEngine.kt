package dev.whyoleg.cryptography

public interface CryptographyEngine {
    public fun <T> get(algorithm: CryptographyAlgorithm<T>): T
}
