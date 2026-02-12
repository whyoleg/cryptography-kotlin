/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal fun NativePlacement.OSSL_PARAM_array(vararg values: CValue<OSSL_PARAM>): CArrayPointer<OSSL_PARAM>? {
    if (values.isEmpty()) return null
    return allocArrayOf(*values, OSSL_PARAM_construct_end())
}

internal fun NativePlacement.OSSL_PARAM_array(vararg values: CValue<OSSL_PARAM>?): CArrayPointer<OSSL_PARAM>? {
    if (values.isEmpty()) return null
    return allocArrayOf(*values.filterNotNull().toTypedArray(), OSSL_PARAM_construct_end())
}

internal fun NativePlacement.OSSL_PARAM_array(values: List<CValue<OSSL_PARAM>?>): CArrayPointer<OSSL_PARAM>? {
    if (values.isEmpty()) return null
    return allocArrayOf(*values.filterNotNull().toTypedArray(), OSSL_PARAM_construct_end())
}

//for stdlib
private inline fun <reified T : CVariable> NativePlacement.allocArrayOf(vararg elements: CValue<T>): CArrayPointer<T> {
    val array = allocArray<T>(elements.size)
    elements.forEachIndexed { index, element -> array[index] = element }
    return array
}

private inline operator fun <reified T : CVariable> CArrayPointer<T>.set(index: Int, value: CValue<T>) {
    value.place(get(index).ptr)
}
