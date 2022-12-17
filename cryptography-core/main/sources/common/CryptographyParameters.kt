package dev.whyoleg.cryptography

public interface CryptographyParameters {
    //TODO: naming?
    public object Empty : CryptographyParameters
}

public abstract class CopyableCryptographyParameters<P : CopyableCryptographyParameters<P, B>, B> : CryptographyParameters {
    protected abstract fun builder(): B
    protected abstract fun build(builder: B): P

    //TODO: inline
    public inline fun copy(block: B.() -> Unit): P = builderInternal().apply(block).let(::buildInternal)

    @PublishedApi
    internal fun builderInternal(): B = builder()

    @PublishedApi
    internal fun buildInternal(builder: B): P = build(builder)
}
