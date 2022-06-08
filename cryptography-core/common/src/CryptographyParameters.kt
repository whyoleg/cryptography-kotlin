package dev.whyoleg.cryptography

public interface CryptographyParameters
public interface CryptographyParametersBuilder<P : CryptographyParameters>

public abstract class CryptographyParametersFactory<
        P : CryptographyParameters,
        B : CryptographyParametersBuilder<P>
        >(
    @PublishedApi
    internal val createBuilder: () -> B,
    @PublishedApi
    internal val build: (B) -> P
) {
    public inline fun create(block: B.() -> Unit): P {
        val builder = createBuilder()
        builder.block()
        return build(builder)
    }
}
