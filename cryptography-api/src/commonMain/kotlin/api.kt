/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

// provider, keys, may be certificates
public interface CryptographyComponent<SELF : CryptographyComponent<SELF>> {
    public operator fun <T> get(tag: Tag<SELF, T>): T

    public interface Tag<C : CryptographyComponent<C>, T>
}

public interface CryptographyProvider : CryptographyComponent<CryptographyProvider> {
    public interface Tag<T> : CryptographyComponent.Tag<CryptographyProvider, T>

    // TODO: registry
    public object Default : CryptographyProvider {
        override fun <T> get(tag: CryptographyComponent.Tag<CryptographyProvider, T>): T {
            TODO("Not yet implemented")
        }
    }
}

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <C : CryptographyComponent<C>, T> CryptographyComponent.Tag<C, T>.invoke(component: C): T = component[this]

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <T> CryptographyProvider.Tag<T>.invoke(
    provider: CryptographyProvider = CryptographyProvider.Default,
): T = provider[this]
