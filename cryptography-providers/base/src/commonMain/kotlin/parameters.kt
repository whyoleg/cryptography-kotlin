/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base

import dev.whyoleg.cryptography.*

// Parameters (curves, digests, sizes, etc.) are resolved by the method receiving them (decoder, generator, signer, derivation creation)
// into the provider-native representation, which is then stored instead of the common parameter.
// Unsupported parameters are reported by the method receiving them when the provider can detect it, otherwise on first use.

// the value is valid for the algorithm, but not supported by the provider (or the environment it runs in)
@CryptographyProviderApi
public fun unsupportedParameter(name: String, value: Any?, cause: Throwable? = null): Nothing =
    throw IllegalStateException("Unsupported $name: $value", cause)

// the value is never valid for the algorithm
@CryptographyProviderApi
public fun invalidParameter(name: String, value: Any?): Nothing =
    throw IllegalArgumentException("Invalid $name: $value")
