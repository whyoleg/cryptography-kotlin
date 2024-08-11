/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import dev.whyoleg.sweetspi.*

@Service
@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyProvider {
    public abstract val name: String

    public abstract fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A?
    public open fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A =
        getOrNull(identifier) ?: throw IllegalStateException("Algorithm not found: $identifier")

    public companion object {
        public val Default: CryptographyProvider by lazy {
            checkNotNull(ServiceLoader.load<CryptographyProvider>().firstOrNull()) {
                "No providers registered. Please provide a dependency or register provider explicitly"
            }
        }
    }
}
