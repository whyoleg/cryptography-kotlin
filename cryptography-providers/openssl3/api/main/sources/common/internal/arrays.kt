package dev.whyoleg.cryptography.openssl3.internal

import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*

internal fun NativePlacement.OSSL_PARAM_array(vararg values: CValue<OSSL_PARAM>): CArrayPointer<OSSL_PARAM> {
    return allocArrayOf(*values, OSSL_PARAM_construct_end())
}

//for stdlib
internal inline fun <reified T : CVariable> NativePlacement.allocArrayOf(vararg elements: CValue<T>): CArrayPointer<T> {
    val array = allocArray<T>(elements.size)
    elements.forEachIndexed { index, element -> array[index] = element }
    return array
}

internal inline operator fun <reified T : CVariable> CArrayPointer<T>.set(index: Int, value: CValue<T>) {
    value.place(get(index).ptr)
}
