package dev.whyoleg.cryptography.hm

import dev.whyoleg.vio.*

//for multi-step operations, like for encrypting or hashing files
public interface CryptographyFunction : Closeable

public interface CryptographyFunctionFactory<P, F : CryptographyFunction> {
    public fun createFunction(parameters: P): F
}

public inline operator fun <P, F : CryptographyFunction, R> CryptographyFunctionFactory<P, F>.invoke(
    parameters: P,
    block: F.() -> R
): R {
    return createFunction(parameters).use(block)
}

public inline operator fun <F : CryptographyFunction, R> CryptographyFunctionFactory<Unit, F>.invoke(
    block: F.() -> R
): R {
    return createFunction(Unit).use(block)
}
