/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*

internal abstract class JdkParametersGenerator<P>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : ParametersGenerator<P> {
    private val algorithmParameterGenerator = state.algorithmParameterGenerator(algorithm)

    protected abstract fun JAlgorithmParameterGenerator.init()

    protected abstract fun JAlgorithmParameters.convert(): P

    final override fun generateParametersBlocking(): P = algorithmParameterGenerator.use {
        it.init()
        it.generateParameters()
    }.convert()
}
