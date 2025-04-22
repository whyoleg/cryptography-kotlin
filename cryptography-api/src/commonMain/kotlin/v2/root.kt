/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.v2

public interface CryptographyProvider {
    public fun <T, P> fetch(tag: T, parameters: P)

    public interface Tag<T, P>

    public object Default : CryptographyProvider {
        override fun <T, P> fetch(tag: T, parameters: P) {
            TODO("Not yet implemented")
        }
    }
}

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <T, P> CryptographyProvider.Tag<T, P>.invoke(
    parameters: P,
    provider: CryptographyProvider = CryptographyProvider.Default,
): T {
    provider.fetch(this, parameters)
}
