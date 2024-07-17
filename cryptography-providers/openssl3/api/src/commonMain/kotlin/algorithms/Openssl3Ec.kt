/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

@OptIn(UnsafeNumber::class)
internal fun decodePublicRawKey(
    curve: EC.Curve,
    input: ByteArray,
): CPointer<EVP_PKEY> = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_name(null, "EC", null))
    try {
        checkError(EVP_PKEY_fromdata_init(context))
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(
            EVP_PKEY_fromdata(
                ctx = context,
                ppkey = pkeyVar.ptr,
                selection = EVP_PKEY_PUBLIC_KEY,
                param = OSSL_PARAM_array(
                    OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert()),
                    OSSL_PARAM_construct_octet_string("pub".cstr.ptr, input.safeRefToU(0), input.size.convert())
                )
            )
        )
        checkError(pkeyVar.value)
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}

@OptIn(UnsafeNumber::class)
internal fun encodePublicRawKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val outVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", null, 0.convert(), outVar.ptr))
    val output = ByteArray(outVar.value.convert())
    checkError(EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", output.safeRefToU(0), output.size.convert(), outVar.ptr))
    output.ensureSizeExactly(outVar.value.convert())
}

@OptIn(UnsafeNumber::class)
internal fun EC_check_key_group(key: CPointer<EVP_PKEY>, expectedCurve: EC.Curve) = memScoped {
    //we need to construct a group, because our EC.Curve names are not the ones, which are used inside openssl
    val expectedGroup = checkError(
        EC_GROUP_new_from_params(
            OSSL_PARAM_array(
                OSSL_PARAM_construct_utf8_string("group".cstr.ptr, expectedCurve.name.cstr.ptr, 0.convert())
            ), null, null
        )
    )
    try {
        val expectedGroupNid = checkError(EC_GROUP_get_curve_name(expectedGroup))
        val expectedGroupName = checkError(OSSL_EC_curve_nid2name(expectedGroupNid)).toKString()

        val keyGroupName = allocArray<ByteVar>(256).also {
            checkError(EVP_PKEY_get_utf8_string_param(key, "group", it, 256.convert(), null))
        }.toKString()

        check(expectedGroupName == keyGroupName) {
            "Wrong curve, expected ${expectedCurve.name}($expectedGroupName) actual $keyGroupName"
        }
    } finally {
        EC_GROUP_free(expectedGroup)
    }
}

internal fun EC_order_size(key: CPointer<EVP_PKEY>): Int = memScoped {
    val orderVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "order", orderVar.ptr))
    val order = checkError(orderVar.value)
    try {
        (checkError(BN_num_bits(order)) + 7) / 8
    } finally {
        BN_free(order)
    }
}
