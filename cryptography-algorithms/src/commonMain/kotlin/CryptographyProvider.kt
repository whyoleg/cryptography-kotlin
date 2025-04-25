/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

// TODO: add interfaces for T and P
// marker interfaces?
//    public interface Service
//    public interface ServiceParameters
//    public fun interface ServiceFactory<S : Any, P : Any> {
//        public fun create(parameters: P): S
//    }

public interface CryptographyProvider : CryptographyComponent<CryptographyProvider> {
    public interface Tag<I : Any, P : Any> : CryptographyComponent.Tag<CryptographyProvider, I, P>

    public companion object Default : CryptographyProvider {
        override fun <I : Any, P : Any> instantiate(
            tag: CryptographyComponent.Tag<CryptographyProvider, I, P>,
            parameters: P,
        ): I {
            TODO("Not yet implemented")
        }

        public fun bootstrap(provider: CryptographyProvider) {

        }
    }
}

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <I : Any, P : Any> CryptographyProvider.Tag<I, P>.invoke(
    parameters: P,
    provider: CryptographyProvider = CryptographyProvider.Default,
): I = provider.instantiate(this, parameters)

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <I : Any> CryptographyProvider.Tag<I, Unit>.invoke(
    provider: CryptographyProvider = CryptographyProvider.Default,
): I = provider.instantiate(this, Unit)
