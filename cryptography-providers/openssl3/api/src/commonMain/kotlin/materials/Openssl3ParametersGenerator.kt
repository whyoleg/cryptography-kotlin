/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal abstract class Openssl3ParametersGenerator<P>(
    private val algorithm: String,
) : ParametersGenerator<P> {
    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?
    protected abstract fun wrapParameters(key: CPointer<EVP_PKEY>): P

    final override fun generateParametersBlocking(): P = with_PKEY_CTX(algorithm) { context ->
        checkError(EVP_PKEY_paramgen_init(context))
        createParams()?.let { checkError(EVP_PKEY_CTX_set_params(context, it)) }
        val paramsKeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(EVP_PKEY_generate(context, paramsKeyVar.ptr))
        wrapParameters(checkError(paramsKeyVar.value))
    }
}
