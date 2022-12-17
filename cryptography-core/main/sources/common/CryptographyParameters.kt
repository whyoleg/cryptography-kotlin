package dev.whyoleg.cryptography

public interface CryptographyParameters {
    public object Empty : CryptographyParameters
}

public abstract class CopyableCryptographyParameters<P : CopyableCryptographyParameters<P, B>, B> : CryptographyParameters {
    protected abstract fun builder(): B
    protected abstract fun build(builder: B): P

    //TODO: inline
    public fun copy(block: B.() -> Unit): P = builder().apply(block).let(::build)
}

public interface CryptographyAlgorithm<T>

public interface CryptographyEngine {
    public fun <T> get(algorithm: CryptographyAlgorithm<T>): T
}
