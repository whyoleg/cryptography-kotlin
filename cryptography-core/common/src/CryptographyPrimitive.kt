package dev.whyoleg.cryptography

public interface CryptographyPrimitive

public interface CryptographyPrimitiveParameters<P : CryptographyPrimitive>

public interface CryptographyPrimitiveProvider {
    public fun <P : CryptographyPrimitive> get(
        parameters: CryptographyPrimitiveParameters<P>
    ): P

    public fun <P : CryptographyPrimitive> getOrNull(
        parameters: CryptographyPrimitiveParameters<P>
    ): P?
}
