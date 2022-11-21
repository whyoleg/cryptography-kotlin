package dev.whyoleg.cryptography.api

public interface CryptographyEngine {
    public fun <R : Any> syncRequest(request: CryptographyRequest<R>): R
    public fun <R : Any> syncRequestOrNull(request: CryptographyRequest<R>): R?
    public suspend fun <R : Any> asyncRequest(request: CryptographyRequest<R>): R
    public suspend fun <R : Any> asyncRequestOrNull(request: CryptographyRequest<R>): R?
}

public interface CryptographyRequest<R : Any>

public interface CryptographyPrimitive {
    public val engine: CryptographyEngine
}
