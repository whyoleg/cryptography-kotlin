package dev.whyoleg.cryptography

public interface CryptographyParameters<P : CryptographyParameters<P, B>, B> {
    public fun copy(block: B.() -> Unit): P //TODO: drop copy
}
