/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*

/**
 * Generates algorithm parameters of type [P].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ParametersGenerator<P> {
    /**
     * Generates new algorithm parameters and returns them.
     *
     * Use [generateParametersBlocking] when calling from non-suspending code.
     */
    public suspend fun generateParameters(): P = generateParametersBlocking()

    /**
     * Generates new algorithm parameters and returns them.
     *
     * Use [generateParameters] when calling from suspending code.
     */
    public fun generateParametersBlocking(): P
}
